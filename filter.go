package main

import (
	"strings"

	log "github.com/sirupsen/logrus"
)

// filterEngine holds all blocking rules and evaluates packets.
type filterEngine struct {
	cfg     *config
	domains map[string]bool
	ips     map[[4]byte]bool
	ipPorts map[ipPortKey]bool
	dnsMode int // 0=drop, 1=poison
}

type ipPortKey struct {
	ip    [4]byte
	port  uint16
	proto uint8 // 6=tcp, 17=udp
}

func newFilterEngine(cfg *config) *filterEngine {
	f := &filterEngine{
		cfg:     cfg,
		domains: make(map[string]bool),
		ips:     make(map[[4]byte]bool),
		ipPorts: make(map[ipPortKey]bool),
	}
	if cfg.DNSMode == "poison" {
		f.dnsMode = 1
	}
	for _, d := range cfg.Domains {
		f.domains[strings.ToLower(d)] = true
	}
	for _, ip := range cfg.IPs {
		var k [4]byte
		copy(k[:], ip)
		f.ips[k] = true
	}
	for _, r := range cfg.IPPorts {
		var k [4]byte
		copy(k[:], r.IP)
		proto := uint8(6) // tcp
		if r.Proto == "udp" {
			proto = 17
		}
		f.ipPorts[ipPortKey{ip: k, port: r.Port, proto: proto}] = true
	}
	return f
}

// ─── packet parser ───────────────────────────────────────────────────────
//
// buf layout: [ eth (14) | ip (20) | transport ... ]
// Returns: action = "pass" | "rst" | "dns-poison" | "drop"
//          plus offsets needed by inject functions

type verdict struct {
	action        string
	tcpOff        int  // offset to TCP header
	udpOff        int
	dnsOff        int
	ifIdx         int
}

func (f *filterEngine) evaluate(buf []byte, n int, ifIdx int) verdict {
	if n < ethHdrLen+ipHdrLen {
		return verdict{action: "pass"}
	}

	// Only IPv4 (eth type 0x0800)
	ethType := u16(buf[12:14])
	if ethType != 0x0800 {
		return verdict{action: "pass"}
	}

	ipOff := ethHdrLen
	ipHdr := buf[ipOff : ipOff+20]

	// Only TCP and UDP
	proto := ipHdr[9]
	ipHdrLen := int(ipHdr[0]&0x0f) * 4
	srcIP := ipHdr[12:16]
	dstIP := ipHdr[16:20]

	var srcKey, dstKey [4]byte
	copy(srcKey[:], srcIP)
	copy(dstKey[:], dstIP)

	transportOff := ipOff + ipHdrLen

	switch proto {
	case 6: // TCP
		if n < transportOff+20 {
			return verdict{action: "pass"}
		}
		tcp := buf[transportOff:]
		dport := u16(tcp[2:4])
		sport := u16(tcp[0:2])
		payloadOff := transportOff + int((tcp[12]>>4)&0x0f)*4

		// 1) IP:Port check
		if f.ipPorts[ipPortKey{ip: dstKey, port: dport, proto: 6}] ||
			f.ipPorts[ipPortKey{ip: srcKey, port: sport, proto: 6}] {
			return verdict{action: "rst", tcpOff: transportOff, ifIdx: ifIdx}
		}
		// 2) IP full block
		if f.ips[dstKey] || f.ips[srcKey] {
			return verdict{action: "rst", tcpOff: transportOff, ifIdx: ifIdx}
		}
		// 3) HTTP / TLS domain check
		if dport == 80 {
			if f.checkHTTP(buf, payloadOff, n) {
				return verdict{action: "drop"}
			}
		}
		if dport == 443 {
			if f.checkTLS(buf, payloadOff, n) {
				return verdict{action: "drop"}
			}
		}

	case 17: // UDP
		if n < transportOff+8 {
			return verdict{action: "pass"}
		}
		udp := buf[transportOff:]
		dport := u16(udp[2:4])
		sport := u16(udp[0:2])
		dnsOff := transportOff + 8

		// 1) IP:Port check
		if f.ipPorts[ipPortKey{ip: dstKey, port: dport, proto: 17}] ||
			f.ipPorts[ipPortKey{ip: srcKey, port: sport, proto: 17}] {
			return verdict{action: "drop"}
		}
		// 2) IP full block
		if f.ips[dstKey] || f.ips[srcKey] {
			return verdict{action: "drop"}
		}
		// 3) DNS check
		if dport == 53 {
			if f.checkDNS(buf, dnsOff, n) {
				if f.dnsMode == 1 {
					return verdict{action: "dns-poison", udpOff: transportOff, dnsOff: dnsOff, ifIdx: ifIdx}
				}
				return verdict{action: "drop"}
			}
		}

	case 1: // ICMP
		if f.ips[dstKey] || f.ips[srcKey] {
			return verdict{action: "drop"}
		}
	}

	return verdict{action: "pass"}
}

// ─── HTTP Host check ─────────────────────────────────────────────────────

func (f *filterEngine) checkHTTP(buf []byte, off, n int) bool {
	if off+16 > n {
		return false
	}
	p := buf[off:]

	// Check HTTP method
	method := b2s(p[:4])
	if !strings.HasPrefix(method, "GET ") && !strings.HasPrefix(method, "POST") &&
		!strings.HasPrefix(method, "PUT ") && !strings.HasPrefix(method, "HEAD") {
		return false
	}

	// Search for "Host: "
	searchEnd := n - off
	if searchEnd > 512 {
		searchEnd = 512
	}
	for i := 0; i < searchEnd-6; i++ {
		if p[i] == 'H' && p[i+1] == 'o' && p[i+2] == 's' &&
			p[i+3] == 't' && p[i+4] == ':' && p[i+5] == ' ' {
			hs := off + i + 6
			he := hs
			for he < n && buf[he] != '\r' && buf[he] != '\n' && buf[he] != ' ' {
				he++
			}
			if he > hs {
				domain := strings.ToLower(string(buf[hs:he]))
				if f.domains[domain] {
					log.WithField("http_host", domain).Debug("blocked HTTP")
					return true
				}
			}
			break
		}
	}
	return false
}

// ─── TLS SNI check ───────────────────────────────────────────────────────

func (f *filterEngine) checkTLS(buf []byte, off, n int) bool {
	if off+9 > n {
		return false
	}
	p := buf[off:]
	// TLS record: content type 0x16, version 0x03xx
	if p[0] != 0x16 || p[1] != 0x03 {
		return false
	}
	// Handshake type 0x01 (ClientHello)
	if p[5] != 0x01 {
		return false
	}

	pos := 43 // skip record(5) + handshake(4) + version(2) + random(32)
	if off+pos+1 > n {
		return false
	}
	pos += 1 + int(p[pos]) // session id

	if off+pos+2 > n {
		return false
	}
	pos += 2 + int(u16(p[pos:pos+2])) // cipher suites

	if off+pos+1 > n {
		return false
	}
	pos += 1 + int(p[pos]) // compression

	if off+pos+2 > n {
		return false
	}
	extLen := int(u16(p[pos : pos+2]))
	pos += 2
	extEnd := pos + extLen
	if off+extEnd > n {
		extEnd = n - off
	}

	for pos+4 <= extEnd {
		extType := u16(p[pos : pos+2])
		elen := int(u16(p[pos+2 : pos+4]))
		pos += 4
		if extType == 0x0000 { // SNI
			if pos+5 > extEnd {
				break
			}
			sniLen := int(u16(p[pos+3 : pos+5]))
			pos += 5
			if pos+sniLen > extEnd {
				break
			}
			domain := strings.ToLower(string(p[pos : pos+sniLen]))
			if f.domains[domain] {
				log.WithField("tls_sni", domain).Debug("blocked TLS")
				return true
			}
			break
		}
		pos += elen
		if pos >= 512 {
			break
		}
	}
	return false
}

// ─── DNS check ────────────────────────────────────────────────────────────

func (f *filterEngine) checkDNS(buf []byte, off, n int) bool {
	if off+12 > n {
		return false
	}
	// Only queries (QR=0)
	flags := u16(buf[off+2 : off+4])
	if flags&0x8000 != 0 {
		return false
	}
	qdcount := u16(buf[off+4 : off+6])
	if qdcount == 0 {
		return false
	}

	// Parse QNAME
	pos := off + 12
	var domain strings.Builder
	for i := 0; i < 64; i++ {
		if pos >= n {
			return false
		}
		lbl := int(buf[pos])
		if lbl == 0 {
			break
		}
		if lbl >= 192 {
			return false
		}
		if domain.Len() > 0 {
			domain.WriteByte('.')
		}
		pos++
		if pos+lbl > n {
			return false
		}
		domain.Write(buf[pos : pos+lbl])
		pos += lbl
	}
	d := strings.ToLower(domain.String())
	if f.domains[d] {
		log.WithField("dns_query", d).Debug("blocked DNS")
		return true
	}
	return false
}

// ─── helpers ─────────────────────────────────────────────────────────────

func contains(list []string, s string) bool {
	for _, item := range list {
		if item == s {
			return true
		}
	}
	return false
}
