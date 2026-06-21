package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"strings"

	log "github.com/sirupsen/logrus"
)

// Filter contains blocking rules and packet evaluation logic
type Filter struct {
	domains map[string]bool // blocked domains (lowercase)
	ips     map[uint32]bool // blocked IPs (as uint32)
	ipPorts map[ipPortKey]bool
}

type ipPortKey struct {
	ip    uint32
	port  uint16
	proto uint8 // 6=TCP, 17=UDP
}

// NewFilter creates a new filter with the given rules
func NewFilter(domainsStr, ipsStr string) *Filter {
	f := &Filter{
		domains: make(map[string]bool),
		ips:     make(map[uint32]bool),
		ipPorts: make(map[ipPortKey]bool),
	}

	// Parse domains
	if domainsStr != "" {
		for _, d := range strings.Split(domainsStr, ",") {
			d = strings.TrimSpace(d)
			if d != "" {
				f.domains[strings.ToLower(d)] = true
			}
		}
	}

	// Parse IPs (simplified, assuming format like "1.2.3.4")
	if ipsStr != "" {
		for _, ipStr := range strings.Split(ipsStr, ",") {
			ipStr = strings.TrimSpace(ipStr)
			if ipStr != "" {
				if ip := parseIP(ipStr); ip != 0 {
					f.ips[ip] = true
				}
			}
		}
	}

	return f
}

// ShouldBlock checks if a packet should be blocked
func (f *Filter) ShouldBlock(packet []byte) bool {
	// packet from NFQUEUE is IP packet (no Ethernet header)
	if len(packet) < 20 {
		return false
	}

	// Parse IP header
	ipVersion := packet[0] >> 4
	if ipVersion != 4 {
		return false // Only IPv4
	}

	proto := packet[9]
	ihl := int(packet[0]&0x0f) * 4
	srcIP := binary.BigEndian.Uint32(packet[12:16])
	dstIP := binary.BigEndian.Uint32(packet[16:20])

	// Check IP blocking
	if f.ips[srcIP] || f.ips[dstIP] {
		log.WithFields(log.Fields{
			"src_ip": ipToString(srcIP),
			"dst_ip": ipToString(dstIP),
		}).Debug("blocked by IP")
		return true
	}

	// Check protocol-specific rules
	switch proto {
	case 6: // TCP
		return f.checkTCP(packet, ihl, dstIP)
	case 17: // UDP
		return f.checkUDP(packet, ihl, dstIP)
	}

	return false
}

// checkTCP checks TCP packets for HTTP/HTTPS
func (f *Filter) checkTCP(packet []byte, ihl int, dstIP uint32) bool {
	if len(packet) < ihl+20 {
		return false
	}

	tcpHdr := packet[ihl:]
	dport := binary.BigEndian.Uint16(tcpHdr[2:4])
	tcpHdrLen := int(tcpHdr[12]>>4) * 4

	// Check IP:Port
	key := ipPortKey{ip: dstIP, port: dport, proto: 6}
	if f.ipPorts[key] {
		log.WithFields(log.Fields{
			"dst_ip":   ipToString(dstIP),
			"dst_port": dport,
			"proto":    "TCP",
		}).Debug("blocked by IP:Port")
		return true
	}

	payload := packet[ihl+tcpHdrLen:]

	// HTTP (port 80)
	if dport == 80 {
		if host := parseHTTPHost(payload); host != "" {
			if f.domains[strings.ToLower(host)] {
				log.WithField("http_host", host).Debug("blocked HTTP")
				return true
			}
		}
	}

	// HTTPS (port 443)
	if dport == 443 {
		if sni := parseTLSSNI(payload); sni != "" {
			if f.domains[strings.ToLower(sni)] {
				log.WithField("tls_sni", sni).Debug("blocked TLS")
				return true
			}
		}
	}

	return false
}

// checkUDP checks UDP packets for DNS
func (f *Filter) checkUDP(packet []byte, ihl int, dstIP uint32) bool {
	if len(packet) < ihl+8 {
		return false
	}

	udpHdr := packet[ihl:]
	dport := binary.BigEndian.Uint16(udpHdr[2:4])

	// Check IP:Port
	key := ipPortKey{ip: dstIP, port: dport, proto: 17}
	if f.ipPorts[key] {
		log.WithFields(log.Fields{
			"dst_ip":   ipToString(dstIP),
			"dst_port": dport,
			"proto":    "UDP",
		}).Debug("blocked by IP:Port")
		return true
	}

	// DNS (port 53)
	if dport == 53 {
		payload := packet[ihl+8:]
		if domain := parseDNS(payload); domain != "" {
			if f.domains[strings.ToLower(domain)] {
				log.WithField("dns_query", domain).Debug("blocked DNS")
				return true
			}
		}
	}

	return false
}

// parseHTTPHost extracts Host header from HTTP request
func parseHTTPHost(payload []byte) string {
	// Look for "Host: " header
	idx := bytes.Index(payload, []byte("\r\nHost: "))
	if idx == -1 {
		// Try at start of request
		if bytes.HasPrefix(payload, []byte("Host: ")) {
			idx = -2 // Will become 0 after +7
		} else {
			return ""
		}
	}

	start := idx + 7 // len("\r\nHost: ") or len("Host: ")
	if start >= len(payload) {
		return ""
	}

	end := bytes.IndexByte(payload[start:], '\r')
	if end == -1 {
		end = bytes.IndexByte(payload[start:], '\n')
	}
	if end == -1 {
		return ""
	}

	return string(payload[start : start+end])
}

// parseTLSSNI extracts SNI from TLS ClientHello
func parseTLSSNI(payload []byte) string {
	// TLS record: type(1) + version(2) + length(2) + handshake
	if len(payload) < 43 {
		return ""
	}

	// Check for handshake (0x16) and ClientHello (0x01)
	if payload[0] != 0x16 || payload[5] != 0x01 {
		return ""
	}

	// Skip to extensions
	// Record: 5 bytes
	// Handshake: type(1) + length(3) + version(2) + random(32) + session_id
	pos := 5 + 4 + 2 + 32

	if pos >= len(payload) {
		return ""
	}

	// Session ID length
	sessionIDLen := int(payload[pos])
	pos += 1 + sessionIDLen

	if pos+2 >= len(payload) {
		return ""
	}

	// Cipher suites length
	cipherSuitesLen := int(binary.BigEndian.Uint16(payload[pos : pos+2]))
	pos += 2 + cipherSuitesLen

	if pos+1 >= len(payload) {
		return ""
	}

	// Compression methods length
	compressionLen := int(payload[pos])
	pos += 1 + compressionLen

	if pos+2 >= len(payload) {
		return ""
	}

	// Extensions length
	extensionsLen := int(binary.BigEndian.Uint16(payload[pos : pos+2]))
	pos += 2

	end := pos + extensionsLen
	if end > len(payload) {
		end = len(payload)
	}

	// Parse extensions
	for pos+4 < end {
		extType := binary.BigEndian.Uint16(payload[pos : pos+2])
		extLen := int(binary.BigEndian.Uint16(payload[pos+2 : pos+4]))
		pos += 4

		if extType == 0 { // SNI extension
			if pos+5 < len(payload) {
				// SNI list length (2) + type (1) + name length (2)
				nameLen := int(binary.BigEndian.Uint16(payload[pos+3 : pos+5]))
				if pos+5+nameLen <= len(payload) {
					return string(payload[pos+5 : pos+5+nameLen])
				}
			}
			return ""
		}

		pos += extLen
	}

	return ""
}

// parseDNS extracts query name from DNS request
func parseDNS(payload []byte) string {
	// DNS header: 12 bytes
	if len(payload) < 13 {
		return ""
	}

	// Start of question section
	pos := 12
	var domain []byte

	for pos < len(payload) {
		labelLen := int(payload[pos])
		if labelLen == 0 {
			break
		}

		// Check for compression (not expected in queries)
		if labelLen >= 0xC0 {
			break
		}

		pos++
		if pos+labelLen > len(payload) {
			return ""
		}

		if len(domain) > 0 {
			domain = append(domain, '.')
		}
		domain = append(domain, payload[pos:pos+labelLen]...)
		pos += labelLen
	}

	return string(domain)
}

// Helper functions
func parseIP(ipStr string) uint32 {
	parts := strings.Split(ipStr, ".")
	if len(parts) != 4 {
		return 0
	}

	var ip uint32
	for i, p := range parts {
		var b uint32
		fmt.Sscanf(p, "%d", &b)
		ip |= (b & 0xFF) << uint(24-i*8)
	}
	return ip
}

func ipToString(ip uint32) string {
	return fmt.Sprintf("%d.%d.%d.%d",
		(ip>>24)&0xFF,
		(ip>>16)&0xFF,
		(ip>>8)&0xFF,
		ip&0xFF)
}

