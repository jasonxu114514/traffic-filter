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

// ─── raw AF_PACKET socket ────────────────────────────────────────────────

func openRawSocket(iface string) (int, int, error) {
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW,
		int(htons(unix.ETH_P_ALL)))
	if err != nil {
		return 0, 0, fmt.Errorf("socket: %w", err)
	}

	ifi, err := net.InterfaceByName(iface)
	if err != nil {
		unix.Close(fd)
		return 0, 0, fmt.Errorf("interface %s: %w", iface, err)
	}

	addr := unix.SockaddrLinklayer{
		Protocol: htons(unix.ETH_P_ALL),
		Ifindex:  ifi.Index,
	}
	if err := unix.Bind(fd, &addr); err != nil {
		unix.Close(fd)
		return 0, 0, fmt.Errorf("bind: %w", err)
	}

	log.WithFields(log.Fields{"iface": iface, "idx": ifi.Index}).Info("raw socket open")
	return fd, ifi.Index, nil
}

func htons(v uint16) uint16 { return (v<<8)&0xff00 | (v>>8)&0x00ff }

// ─── TCP RST injection ───────────────────────────────────────────────────

func sendTCPRST(fd int, buf []byte, eth [14]byte, ip [20]byte,
	tcpOff int, ifIdx int) {

	var pkt [54]byte

	// Ethernet: swap mac
	copy(pkt[0:6], eth[6:12])
	copy(pkt[6:12], eth[0:6])
	pkt[12] = eth[12]; pkt[13] = eth[13]

	// IP: swap saddr/daddr (ip[12:16]=src, ip[16:20]=dst)
	copy(pkt[14:34], ip[:])
	copy(pkt[26:30], ip[16:20]) // new src = orig dst
	copy(pkt[30:34], ip[12:16]) // new dst = orig src
	// IP total len = 20 + 20 = 40
	pkt[16] = 0; pkt[17] = 40
	pkt[24] = 0; pkt[25] = 0
	cs := ipChecksum(pkt[14:34])
	pkt[24] = byte(cs); pkt[25] = byte(cs >> 8)

	// TCP
	copy(pkt[34:54], buf[tcpOff:tcpOff+20])
	// swap ports
	pkt[34], pkt[35] = buf[tcpOff+2], buf[tcpOff+3]
	pkt[36], pkt[37] = buf[tcpOff+0], buf[tcpOff+1]

	origFlags := buf[tcpOff+13]
	origSeq := u32(buf[tcpOff+4:])
	origDO := (buf[tcpOff+12] >> 4) & 0x0f

	var seq, ack uint32
	if origFlags&0x10 != 0 { // ACK
		seq = u32(buf[tcpOff+8:]) // echo their ack as our seq
		ack = origSeq + 1
	} else {
		if origFlags&0x02 != 0 { // SYN
			ack = origSeq + 1
		} else {
			ack = origSeq
		}
	}

	putU32(pkt[38:], seq)
	putU32(pkt[42:], ack)
	pkt[46] = (origDO << 4) | 0x14 // dataoff=orig, RST+ACK
	pkt[47] = 0 // window=0
	pkt[48] = 0; pkt[49] = 0
	pkt[50] = 0; pkt[51] = 0

	cs2 := tcpCS4(pkt[26:30], pkt[30:34], pkt[34:54])
	pkt[50] = byte(cs2 >> 8); pkt[51] = byte(cs2)

	sendPkt(fd, pkt[:], ifIdx)
}

// ─── DNS poison injection ────────────────────────────────────────────────

func sendDNSPoison(fd int, buf []byte, eth [14]byte, ip [20]byte,
	udpOff, dnsOff, ifIdx int) {

	dnsLen := len(buf) - dnsOff
	respLen := 14 + 20 + 8 + dnsLen
	resp := make([]byte, respLen)

	// Ethernet
	copy(resp[0:6], eth[6:12])
	copy(resp[6:12], eth[0:6])
	resp[12] = eth[12]; resp[13] = eth[13]

	// IP: swap saddr/daddr (ip[12:16]=src, ip[16:20]=dst)
	copy(resp[14:34], ip[:])
	copy(resp[26:30], ip[16:20]) // new src = orig dst
	copy(resp[30:34], ip[12:16]) // new dst = orig src
	ipLen := uint16(20 + 8 + dnsLen)
	resp[16] = byte(ipLen >> 8); resp[17] = byte(ipLen)
	resp[24] = 0; resp[25] = 0
	cs := ipChecksum(resp[14:34])
	resp[24] = byte(cs); resp[25] = byte(cs >> 8)

	// UDP: swap ports
	copy(resp[34:42], buf[udpOff:udpOff+8])
	resp[34], resp[35] = buf[udpOff+2], buf[udpOff+3]
	resp[36], resp[37] = buf[udpOff+0], buf[udpOff+1]
	udpLen := uint16(8 + dnsLen)
	resp[38] = byte(udpLen >> 8); resp[39] = byte(udpLen)
	resp[40] = 0; resp[41] = 0

	// DNS: response + NXDOMAIN (RCODE=3)
	copy(resp[42:], buf[dnsOff:])
	resp[42+2] = 0x81 // QR=1, RD=1
	resp[42+3] = 0x83 // RA=1, RCODE=3
	resp[42+6] = 0; resp[42+7] = 0 // ancount=0

	sendPkt(fd, resp, ifIdx)
}

func sendPkt(fd int, data []byte, ifIdx int) {
	addr := unix.SockaddrLinklayer{
		Protocol: htons(unix.ETH_P_IP),
		Ifindex:  ifIdx,
	}
	unix.Sendto(fd, data, 0, &addr)
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
