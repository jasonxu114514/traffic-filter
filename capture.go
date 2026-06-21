package main

import (
	"fmt"
	"net"
	"unsafe"

	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
)

const (
	ethHdrLen = 14
	ipHdrLen  = 20
	tcpHdrLen = 20
	udpHdrLen = 8
	maxBufSz  = 65536
)

// ─── sockets ─────────────────────────────────────────────────────────────

// captureSock is the AF_PACKET socket for reading packets.
// injectSock is the AF_INET raw socket for sending RST/poison.
var injectSock int

func openSockets(iface string) (capFD, ifIdx int, err error) {
	// Capture socket: AF_PACKET
	capFD, err = unix.Socket(unix.AF_PACKET, unix.SOCK_RAW,
		int(htons(unix.ETH_P_ALL)))
	if err != nil {
		return 0, 0, fmt.Errorf("capture socket: %w", err)
	}

	ifi, err := net.InterfaceByName(iface)
	if err != nil {
		unix.Close(capFD)
		return 0, 0, fmt.Errorf("interface %s: %w", iface, err)
	}

	addr := unix.SockaddrLinklayer{
		Protocol: htons(unix.ETH_P_ALL),
		Ifindex:  ifi.Index,
	}
	if err := unix.Bind(capFD, &addr); err != nil {
		unix.Close(capFD)
		return 0, 0, fmt.Errorf("bind: %w", err)
	}

	// Injection socket: AF_INET + IPPROTO_RAW (full IP header control)
	injectSock, err = unix.Socket(unix.AF_INET, unix.SOCK_RAW, unix.IPPROTO_RAW)
	if err != nil {
		unix.Close(capFD)
		return 0, 0, fmt.Errorf("inject socket: %w", err)
	}
	// Tell kernel we'll provide our own IP header
	on := 1
	unix.SetsockoptInt(injectSock, unix.IPPROTO_IP, unix.IP_HDRINCL, on)

	log.WithFields(log.Fields{"iface": iface, "idx": ifi.Index}).Info("sockets open")
	return capFD, ifi.Index, nil
}

func htons(v uint16) uint16 { return (v<<8)&0xff00 | (v>>8)&0x00ff }

// ─── TCP RST injection (via AF_INET raw socket) ──────────────────────────

func sendTCPRST(buf []byte, ip [20]byte, tcpOff int) {
	srcIP := ip[12:16]   // client IP
	dstIP := ip[16:20]   // server IP
	srcPort := u16(buf[tcpOff : tcpOff+2])
	dstPort := u16(buf[tcpOff+2 : tcpOff+4])
	origSeq := u32(buf[tcpOff+4:])
	origAck := u32(buf[tcpOff+8:])
	origFlags := buf[tcpOff+13]
	origDO := (buf[tcpOff+12] >> 4) & 0x0f

	// Build IP + TCP RST packet
	ipPkt := make([]byte, 20+20)

	// IP header
	ipPkt[0] = 0x45              // v4, IHL=5
	ipPkt[1] = 0                 // DSCP/ECN
	ipPkt[2] = 0; ipPkt[3] = 40 // total len = 40
	ipPkt[4] = 0; ipPkt[5] = 0  // ID
	ipPkt[6] = 0x40; ipPkt[7] = 0 // flags, frag
	ipPkt[8] = 64                // TTL
	ipPkt[9] = 6                 // TCP
	// checksum at 10-11 (fill later)
	copy(ipPkt[12:16], dstIP) // src = server (pretend)
	copy(ipPkt[16:20], srcIP) // dst = client

	cs := ipChecksum(ipPkt[:20])
	ipPkt[10] = byte(cs >> 8); ipPkt[11] = byte(cs)

	// TCP header
	tcpH := ipPkt[20:]
	tcpH[0] = byte(dstPort >> 8); tcpH[1] = byte(dstPort) // src = server port
	tcpH[2] = byte(srcPort >> 8); tcpH[3] = byte(srcPort) // dst = client port

	var seq, ack uint32
	if origFlags&0x10 != 0 { // original had ACK
		// Client sent data → echo client's ack_seq as our seq, ack = client's seq + data_len
		ipTotal := u16(buf[16:18])
		ipHL := int(buf[14]&0x0f) * 4
		tcpHL := int((buf[tcpOff+12]>>4)&0x0f) * 4
		dataLen := int(ipTotal) - ipHL - tcpHL
		seq = origAck
		ack = origSeq + uint32(dataLen)
	} else {
		if origFlags&0x02 != 0 { // SYN
			ack = origSeq + 1
		} else {
			ack = origSeq
		}
	}

	putU32(tcpH[4:], seq)
	putU32(tcpH[8:], ack)
	tcpH[12] = (origDO << 4) // data offset (same as original)
	tcpH[13] = 0x14          // RST+ACK
	tcpH[14] = 0; tcpH[15] = 0 // window=0
	tcpH[16] = 0; tcpH[17] = 0 // checksum placeholder
	tcpH[18] = 0; tcpH[19] = 0 // urgent=0

	tcpCS := tcpCS4(dstIP, srcIP, tcpH)
	tcpH[16] = byte(tcpCS >> 8); tcpH[17] = byte(tcpCS)

	// Send to client
	var sa unix.SockaddrInet4
	copy(sa.Addr[:], srcIP)
	unix.Sendto(injectSock, ipPkt, 0, &sa)
}

// ─── DNS poison injection (via AF_INET raw socket) ───────────────────────

func sendDNSPoison(buf []byte, ip [20]byte, udpOff, dnsOff int) {
	srcIP := ip[12:16]
	dstIP := ip[16:20]
	srcPort := u16(buf[udpOff : udpOff+2])
	dstPort := u16(buf[udpOff+2 : udpOff+4])
	dnsLen := len(buf) - dnsOff

	udpLen := 8 + dnsLen
	ipTot := 20 + udpLen
	ipPkt := make([]byte, ipTot)

	// IP header
	ipPkt[0] = 0x45
	ipPkt[2] = byte(ipTot >> 8); ipPkt[3] = byte(ipTot)
	ipPkt[6] = 0x40
	ipPkt[8] = 64
	ipPkt[9] = 17 // UDP
	copy(ipPkt[12:16], dstIP) // src = DNS server
	copy(ipPkt[16:20], srcIP) // dst = client

	cs := ipChecksum(ipPkt[:20])
	ipPkt[10] = byte(cs >> 8); ipPkt[11] = byte(cs)

	// UDP header
	udpH := ipPkt[20:]
	udpH[0] = byte(dstPort >> 8); udpH[1] = byte(dstPort)
	udpH[2] = byte(srcPort >> 8); udpH[3] = byte(srcPort)
	udpH[4] = byte(udpLen >> 8); udpH[5] = byte(udpLen)
	udpH[6] = 0; udpH[7] = 0 // checksum 0

	// DNS: copy original query, modify flags → response + NXDOMAIN
	copy(ipPkt[28:], buf[dnsOff:])
	ipPkt[28+2] = 0x81 // QR=1, RD=1
	ipPkt[28+3] = 0x83 // RA=1, RCODE=3
	ipPkt[28+6] = 0; ipPkt[28+7] = 0 // ancount=0

	var sa unix.SockaddrInet4
	copy(sa.Addr[:], srcIP)
	unix.Sendto(injectSock, ipPkt, 0, &sa)
}

// ─── checksums ───────────────────────────────────────────────────────────

func ipChecksum(hdr []byte) uint16 {
	sum := uint32(0)
	for i := 0; i < len(hdr)-1; i += 2 {
		sum += uint32(hdr[i])<<8 | uint32(hdr[i+1])
	}
	sum = (sum >> 16) + (sum & 0xffff)
	sum += sum >> 16
	return uint16(^sum)
}

func tcpCS4(srcIP, dstIP, tcpHdr []byte) uint16 {
	sum := uint32(0)
	sum += uint32(srcIP[0])<<8 | uint32(srcIP[1])
	sum += uint32(srcIP[2])<<8 | uint32(srcIP[3])
	sum += uint32(dstIP[0])<<8 | uint32(dstIP[1])
	sum += uint32(dstIP[2])<<8 | uint32(dstIP[3])
	sum += 6 // IPPROTO_TCP
	sum += uint32(len(tcpHdr))
	for i := 0; i < len(tcpHdr)-1; i += 2 {
		sum += uint32(tcpHdr[i])<<8 | uint32(tcpHdr[i+1])
	}
	if len(tcpHdr)%2 != 0 {
		sum += uint32(tcpHdr[len(tcpHdr)-1]) << 8
	}
	sum = (sum >> 16) + (sum & 0xffff)
	sum += sum >> 16
	return uint16(^sum)
}

// ─── parsers ─────────────────────────────────────────────────────────────

func u16(b []byte) uint16 { return uint16(b[0])<<8 | uint16(b[1]) }
func u32(b []byte) uint32 {
	return uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
}
func putU32(b []byte, v uint32) {
	b[0] = byte(v >> 24); b[1] = byte(v >> 16)
	b[2] = byte(v >> 8); b[3] = byte(v)
}

func b2s(b []byte) string { return *(*string)(unsafe.Pointer(&b)) }
