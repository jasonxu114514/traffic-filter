package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

type verdictKind int

const (
	verdictAccept verdictKind = iota
	verdictDrop
)

type blockReason int

const (
	reasonNone blockReason = iota
	reasonHTTP
	reasonTLS
	reasonDNSPoison
	reasonDNSDrop
	reasonIP
	reasonIPPort
	reasonMalformed
)

type packetVerdict struct {
	Kind        verdictKind
	Reason      blockReason
	DNSResponse *dnsResponse
}

type dnsResponse struct {
	Payload []byte
	SrcIP   netip.Addr
	DstIP   netip.Addr
	SrcPort uint16
	DstPort uint16
}

type packetClassifier struct {
	rules   RuleSet
	dnsMode string
}

func newPacketClassifier(rules RuleSet, dnsMode string) packetClassifier {
	return packetClassifier{
		rules:   rules,
		dnsMode: dnsMode,
	}
}

func (c packetClassifier) Classify(payload []byte) packetVerdict {
	if len(payload) == 0 {
		return packetVerdict{Kind: verdictAccept, Reason: reasonMalformed}
	}

	switch payload[0] >> 4 {
	case 4:
		return c.classifyIPv4(payload)
	case 6:
		return c.classifyIPv6(payload)
	default:
		return packetVerdict{Kind: verdictAccept, Reason: reasonMalformed}
	}
}

func (c packetClassifier) classifyIPv4(payload []byte) packetVerdict {
	packet := gopacket.NewPacket(payload, layers.LayerTypeIPv4, gopacket.NoCopy)
	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	if ipLayer == nil {
		return packetVerdict{Kind: verdictAccept, Reason: reasonMalformed}
	}
	ip4 := ipLayer.(*layers.IPv4)

	src, srcOK := addrFromIP(ip4.SrcIP)
	dst, dstOK := addrFromIP(ip4.DstIP)
	if !srcOK || !dstOK {
		return packetVerdict{Kind: verdictAccept, Reason: reasonMalformed}
	}
	if c.rules.matchIP(src) || c.rules.matchIP(dst) {
		return packetVerdict{Kind: verdictDrop, Reason: reasonIP}
	}

	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		tcp := tcpLayer.(*layers.TCP)
		return c.classifyTCP(src, dst, uint16(tcp.SrcPort), uint16(tcp.DstPort), tcp.Payload)
	}
	if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
		udp := udpLayer.(*layers.UDP)
		return c.classifyUDP(udp, src, dst)
	}

	return packetVerdict{Kind: verdictAccept}
}

func (c packetClassifier) classifyIPv6(payload []byte) packetVerdict {
	packet := gopacket.NewPacket(payload, layers.LayerTypeIPv6, gopacket.NoCopy)
	ipLayer := packet.Layer(layers.LayerTypeIPv6)
	if ipLayer == nil {
		return packetVerdict{Kind: verdictAccept, Reason: reasonMalformed}
	}
	ip6 := ipLayer.(*layers.IPv6)

	src, srcOK := addrFromIP(ip6.SrcIP)
	dst, dstOK := addrFromIP(ip6.DstIP)
	if !srcOK || !dstOK {
		return packetVerdict{Kind: verdictAccept, Reason: reasonMalformed}
	}
	if c.rules.matchIP(src) || c.rules.matchIP(dst) {
		return packetVerdict{Kind: verdictDrop, Reason: reasonIP}
	}

	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		tcp := tcpLayer.(*layers.TCP)
		return c.classifyTCP(src, dst, uint16(tcp.SrcPort), uint16(tcp.DstPort), tcp.Payload)
	}
	if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
		udp := udpLayer.(*layers.UDP)
		return c.classifyUDP(udp, src, dst)
	}

	return packetVerdict{Kind: verdictAccept}
}

func (c packetClassifier) classifyTCP(src, dst netip.Addr, sport, dport uint16, payload []byte) packetVerdict {
	if c.rules.matchIPPort(src, sport, protoTCP) || c.rules.matchIPPort(dst, dport, protoTCP) {
		return packetVerdict{Kind: verdictDrop, Reason: reasonIPPort}
	}

	switch dport {
	case 80:
		host := httpHost(payload)
		if host != "" && c.rules.matchDomain(host) {
			return packetVerdict{Kind: verdictDrop, Reason: reasonHTTP}
		}
	case 443:
		sni := tlsSNI(payload)
		if sni != "" && c.rules.matchDomain(sni) {
			return packetVerdict{Kind: verdictDrop, Reason: reasonTLS}
		}
	}

	return packetVerdict{Kind: verdictAccept}
}

func (c packetClassifier) classifyUDP(udp *layers.UDP, src, dst netip.Addr) packetVerdict {
	sport := uint16(udp.SrcPort)
	dport := uint16(udp.DstPort)
	if c.rules.matchIPPort(src, sport, protoUDP) || c.rules.matchIPPort(dst, dport, protoUDP) {
		return packetVerdict{Kind: verdictDrop, Reason: reasonIPPort}
	}
	if dport != 53 {
		return packetVerdict{Kind: verdictAccept}
	}

	dns, qname, ok := parseDNSQuery(udp.Payload)
	if !ok || !c.rules.matchDNSPoison(qname) {
		return packetVerdict{Kind: verdictAccept}
	}
	if c.dnsMode == "drop" {
		return packetVerdict{Kind: verdictDrop, Reason: reasonDNSDrop}
	}

	resp, err := buildDNSNXDomainPayload(dns)
	if err != nil {
		return packetVerdict{Kind: verdictDrop, Reason: reasonDNSDrop}
	}
	return packetVerdict{
		Kind:   verdictDrop,
		Reason: reasonDNSPoison,
		DNSResponse: &dnsResponse{
			Payload: resp,
			SrcIP:   dst,
			DstIP:   src,
			SrcPort: dport,
			DstPort: sport,
		},
	}
}

func addrFromIP(ip net.IP) (netip.Addr, bool) {
	addr, ok := netip.AddrFromSlice(ip)
	if ok {
		return addr.Unmap(), true
	}
	if v4 := ip.To4(); v4 != nil {
		addr, ok = netip.AddrFromSlice(v4)
		return addr.Unmap(), ok
	}
	return netip.Addr{}, false
}

func httpHost(payload []byte) string {
	const header = "\r\nhost:"
	lower := bytes.ToLower(payload)
	idx := -1

	if bytes.HasPrefix(lower, []byte("host:")) {
		idx = 0
	} else if pos := bytes.Index(lower, []byte(header)); pos >= 0 {
		idx = pos + 2
	}
	if idx < 0 {
		return ""
	}

	start := idx + len("host:")
	for start < len(payload) && (payload[start] == ' ' || payload[start] == '\t') {
		start++
	}
	end := start
	for end < len(payload) {
		switch payload[end] {
		case '\r', '\n', ' ', '\t':
			return string(payload[start:end])
		case ':':
			return string(payload[start:end])
		default:
			end++
		}
	}
	return string(payload[start:end])
}

func tlsSNI(payload []byte) string {
	if len(payload) < 5 || payload[0] != 0x16 || payload[1] != 0x03 {
		return ""
	}
	recordLen := int(binary.BigEndian.Uint16(payload[3:5]))
	if recordLen <= 0 || 5+recordLen > len(payload) {
		return ""
	}
	body := payload[5 : 5+recordLen]
	if len(body) < 42 || body[0] != 0x01 {
		return ""
	}

	pos := 4 + 2 + 32
	if pos >= len(body) {
		return ""
	}
	sessionLen := int(body[pos])
	pos += 1 + sessionLen
	if pos+2 > len(body) {
		return ""
	}
	cipherLen := int(binary.BigEndian.Uint16(body[pos : pos+2]))
	pos += 2 + cipherLen
	if pos >= len(body) {
		return ""
	}
	compressionLen := int(body[pos])
	pos += 1 + compressionLen
	if pos+2 > len(body) {
		return ""
	}
	extensionsLen := int(binary.BigEndian.Uint16(body[pos : pos+2]))
	pos += 2
	if pos+extensionsLen > len(body) {
		return ""
	}
	end := pos + extensionsLen

	for pos+4 <= end {
		extType := binary.BigEndian.Uint16(body[pos : pos+2])
		extLen := int(binary.BigEndian.Uint16(body[pos+2 : pos+4]))
		pos += 4
		if pos+extLen > end {
			return ""
		}
		if extType != 0 {
			pos += extLen
			continue
		}
		if extLen < 5 {
			return ""
		}
		nameType := body[pos+2]
		nameLen := int(binary.BigEndian.Uint16(body[pos+3 : pos+5]))
		if nameType != 0 || nameLen <= 0 || pos+5+nameLen > pos+extLen {
			return ""
		}
		return string(body[pos+5 : pos+5+nameLen])
	}

	return ""
}

func parseDNSQuery(payload []byte) (layers.DNS, string, bool) {
	var dns layers.DNS
	if err := dns.DecodeFromBytes(payload, gopacket.NilDecodeFeedback); err != nil {
		return dns, "", false
	}
	if dns.QR || len(dns.Questions) == 0 {
		return dns, "", false
	}
	return dns, string(dns.Questions[0].Name), true
}

func buildDNSNXDomainPayload(dns layers.DNS) ([]byte, error) {
	respDNS := dnsNXDomain(dns)
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true}
	if err := gopacket.SerializeLayers(buf, opts, &respDNS); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func dnsNXDomain(query layers.DNS) layers.DNS {
	return layers.DNS{
		ID:           query.ID,
		QR:           true,
		OpCode:       query.OpCode,
		RD:           query.RD,
		RA:           false,
		ResponseCode: layers.DNSResponseCodeNXDomain,
		Questions:    query.Questions,
	}
}

func reasonString(reason blockReason) string {
	switch reason {
	case reasonHTTP:
		return "http"
	case reasonTLS:
		return "tls"
	case reasonDNSPoison:
		return "dns_poison"
	case reasonDNSDrop:
		return "dns_drop"
	case reasonIP:
		return "ip"
	case reasonIPPort:
		return "ip_port"
	case reasonMalformed:
		return "malformed"
	default:
		return "none"
	}
}

func packetSummary(payload []byte) string {
	if len(payload) == 0 {
		return "empty"
	}
	return fmt.Sprintf("ipv%d len=%d", payload[0]>>4, len(payload))
}
