//go:build xdp && linux

package main

import (
	"bytes"
	_ "embed"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	log "github.com/sirupsen/logrus"
)

//go:embed bpf/filter.bpf.o
var bpfProgram []byte

const (
	maxDomainLen = 64

	domainHTTP      uint32 = 1
	domainTLS       uint32 = 2
	domainDNSPoison uint32 = 4

	protoTCP uint8 = 6
	protoUDP uint8 = 17
)

var statNames = []string{
	"total",
	"passed",
	"http_blocked",
	"tls_blocked",
	"dns_poisoned",
	"ip_blocked",
	"ip_port_blocked",
	"malformed",
}

type domainKey [maxDomainLen]byte

type lpmV4Key struct {
	PrefixLen uint32
	Addr      uint32
}

type lpmV6Key struct {
	PrefixLen uint32
	Addr      [16]byte
}

type ipPortKey struct {
	Addr  uint32
	Port  uint16
	Proto uint8
	Pad   uint8
}

type ipPortV6Key struct {
	Addr  [16]byte
	Port  uint16
	Proto uint8
	Pad   uint8
}

type XDPFilter struct {
	program       *ebpf.Program
	ipv4Program   *ebpf.Program
	ipv6Program   *ebpf.Program
	tcp4Program   *ebpf.Program
	udp4Program   *ebpf.Program
	tcp6Program   *ebpf.Program
	udp6Program   *ebpf.Program
	http4Program  *ebpf.Program
	tls4Program   *ebpf.Program
	http6Program  *ebpf.Program
	tls6Program   *ebpf.Program
	dns4Program   *ebpf.Program
	dns6Program   *ebpf.Program
	dispatchRules *ebpf.Map
	scratchDomain *ebpf.Map
	domainRules   *ebpf.Map
	cidrRules     *ebpf.Map
	cidrV6Rules   *ebpf.Map
	ipPortRules   *ebpf.Map
	ipPortV6Rules *ebpf.Map
	stats         *ebpf.Map
	xdpLink       link.Link
	iface         string
}

func NewXDPFilter(ifaceName, mode string) (*XDPFilter, error) {
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("remove memlock rlimit: %w", err)
	}

	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(bpfProgram))
	if err != nil {
		return nil, fmt.Errorf("load eBPF spec: %w", err)
	}

	objs := struct {
		Program       *ebpf.Program `ebpf:"xdp_filter"`
		IPv4Program   *ebpf.Program `ebpf:"xdp_ipv4"`
		IPv6Program   *ebpf.Program `ebpf:"xdp_ipv6"`
		TCP4Program   *ebpf.Program `ebpf:"xdp_tcp4"`
		UDP4Program   *ebpf.Program `ebpf:"xdp_udp4"`
		TCP6Program   *ebpf.Program `ebpf:"xdp_tcp6"`
		UDP6Program   *ebpf.Program `ebpf:"xdp_udp6"`
		HTTP4Program  *ebpf.Program `ebpf:"xdp_http4"`
		TLS4Program   *ebpf.Program `ebpf:"xdp_tls4"`
		HTTP6Program  *ebpf.Program `ebpf:"xdp_http6"`
		TLS6Program   *ebpf.Program `ebpf:"xdp_tls6"`
		DNS4Program   *ebpf.Program `ebpf:"xdp_dns4"`
		DNS6Program   *ebpf.Program `ebpf:"xdp_dns6"`
		DispatchRules *ebpf.Map     `ebpf:"dispatch_rules"`
		ScratchDomain *ebpf.Map     `ebpf:"scratch_domain"`
		DomainRules   *ebpf.Map     `ebpf:"domain_rules"`
		CidrRules     *ebpf.Map     `ebpf:"cidr_rules"`
		CidrV6Rules   *ebpf.Map     `ebpf:"cidr_v6_rules"`
		IPPortRules   *ebpf.Map     `ebpf:"ip_port_rules"`
		IPPortV6Rules *ebpf.Map     `ebpf:"ip_port_v6_rules"`
		Stats         *ebpf.Map     `ebpf:"stats"`
	}{}

	if err := spec.LoadAndAssign(&objs, nil); err != nil {
		return nil, fmt.Errorf("load eBPF objects: %w", err)
	}

	if err := populateDispatchRules(objs.DispatchRules, objs.IPv4Program, objs.IPv6Program, objs.TCP4Program, objs.UDP4Program, objs.TCP6Program, objs.UDP6Program, objs.HTTP4Program, objs.TLS4Program, objs.HTTP6Program, objs.TLS6Program, objs.DNS4Program, objs.DNS6Program); err != nil {
		closeObjects(objs.Program, objs.IPv4Program, objs.IPv6Program, objs.TCP4Program, objs.UDP4Program, objs.TCP6Program, objs.UDP6Program, objs.HTTP4Program, objs.TLS4Program, objs.HTTP6Program, objs.TLS6Program, objs.DNS4Program, objs.DNS6Program, objs.DispatchRules, objs.ScratchDomain, objs.DomainRules, objs.CidrRules, objs.CidrV6Rules, objs.IPPortRules, objs.IPPortV6Rules, objs.Stats)
		return nil, err
	}

	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		closeObjects(objs.Program, objs.IPv4Program, objs.IPv6Program, objs.TCP4Program, objs.UDP4Program, objs.TCP6Program, objs.UDP6Program, objs.HTTP4Program, objs.TLS4Program, objs.HTTP6Program, objs.TLS6Program, objs.DNS4Program, objs.DNS6Program, objs.DispatchRules, objs.ScratchDomain, objs.DomainRules, objs.CidrRules, objs.CidrV6Rules, objs.IPPortRules, objs.IPPortV6Rules, objs.Stats)
		return nil, fmt.Errorf("find interface %s: %w", ifaceName, err)
	}

	flags, err := xdpAttachFlags(mode)
	if err != nil {
		closeObjects(objs.Program, objs.IPv4Program, objs.IPv6Program, objs.TCP4Program, objs.UDP4Program, objs.TCP6Program, objs.UDP6Program, objs.HTTP4Program, objs.TLS4Program, objs.HTTP6Program, objs.TLS6Program, objs.DNS4Program, objs.DNS6Program, objs.DispatchRules, objs.ScratchDomain, objs.DomainRules, objs.CidrRules, objs.CidrV6Rules, objs.IPPortRules, objs.IPPortV6Rules, objs.Stats)
		return nil, err
	}

	xdpLink, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.Program,
		Interface: iface.Index,
		Flags:     flags,
	})
	if err != nil {
		closeObjects(objs.Program, objs.IPv4Program, objs.IPv6Program, objs.TCP4Program, objs.UDP4Program, objs.TCP6Program, objs.UDP6Program, objs.HTTP4Program, objs.TLS4Program, objs.HTTP6Program, objs.TLS6Program, objs.DNS4Program, objs.DNS6Program, objs.DispatchRules, objs.ScratchDomain, objs.DomainRules, objs.CidrRules, objs.CidrV6Rules, objs.IPPortRules, objs.IPPortV6Rules, objs.Stats)
		return nil, fmt.Errorf("attach XDP to %s: %w", ifaceName, err)
	}

	log.WithFields(log.Fields{
		"interface": ifaceName,
		"mode":      mode,
	}).Info("XDP program attached")

	return &XDPFilter{
		program:       objs.Program,
		ipv4Program:   objs.IPv4Program,
		ipv6Program:   objs.IPv6Program,
		tcp4Program:   objs.TCP4Program,
		udp4Program:   objs.UDP4Program,
		tcp6Program:   objs.TCP6Program,
		udp6Program:   objs.UDP6Program,
		http4Program:  objs.HTTP4Program,
		tls4Program:   objs.TLS4Program,
		http6Program:  objs.HTTP6Program,
		tls6Program:   objs.TLS6Program,
		dns4Program:   objs.DNS4Program,
		dns6Program:   objs.DNS6Program,
		dispatchRules: objs.DispatchRules,
		scratchDomain: objs.ScratchDomain,
		domainRules:   objs.DomainRules,
		cidrRules:     objs.CidrRules,
		cidrV6Rules:   objs.CidrV6Rules,
		ipPortRules:   objs.IPPortRules,
		ipPortV6Rules: objs.IPPortV6Rules,
		stats:         objs.Stats,
		xdpLink:       xdpLink,
		iface:         ifaceName,
	}, nil
}

func populateDispatchRules(dispatch *ebpf.Map, ipv4, ipv6, tcp4, udp4, tcp6, udp6, http4, tls4, http6, tls6, dns4, dns6 *ebpf.Program) error {
	if dispatch == nil {
		return errors.New("dispatch_rules map is missing")
	}
	if ipv4 == nil || ipv6 == nil || tcp4 == nil || udp4 == nil || tcp6 == nil || udp6 == nil || http4 == nil || tls4 == nil || http6 == nil || tls6 == nil || dns4 == nil || dns6 == nil {
		return errors.New("dispatch programs are missing")
	}

	programs := []*ebpf.Program{ipv4, ipv6, tcp4, udp4, tcp6, udp6, http4, tls4, http6, tls6, dns4, dns6}
	for i, program := range programs {
		key := uint32(i)
		if err := dispatch.Put(&key, program); err != nil {
			return fmt.Errorf("put dispatch program %d: %w", i, err)
		}
	}

	return nil
}

func xdpAttachFlags(mode string) (link.XDPAttachFlags, error) {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "", "generic":
		return link.XDPGenericMode, nil
	case "driver", "native":
		return link.XDPDriverMode, nil
	case "auto":
		return 0, nil
	default:
		return 0, fmt.Errorf("unknown XDP mode %q (use generic, driver, or auto)", mode)
	}
}

func closeObjects(objs ...interface{ Close() error }) {
	for _, obj := range objs {
		if obj != nil {
			_ = obj.Close()
		}
	}
}

func (f *XDPFilter) AddDomainRule(domain string, flags uint32) (string, error) {
	key, normalized, err := makeDomainKey(domain)
	if err != nil {
		return "", err
	}

	var existing uint32
	if err := f.domainRules.Lookup(&key, &existing); err == nil {
		flags |= existing
	}

	if err := f.domainRules.Put(&key, flags); err != nil {
		return "", fmt.Errorf("put domain rule %s: %w", normalized, err)
	}

	return normalized, nil
}

func (f *XDPFilter) AddCIDR(prefix netip.Prefix) (string, error) {
	prefix = prefix.Masked()
	val := uint32(1)

	if prefix.Addr().Is4() {
		addr, err := ipv4MapUint32(prefix.Addr())
		if err != nil {
			return "", err
		}
		ones := prefix.Bits()
		if ones < 0 || ones > 32 {
			return "", fmt.Errorf("invalid IPv4 prefix %s", prefix.String())
		}

		key := lpmV4Key{
			PrefixLen: uint32(ones),
			Addr:      addr,
		}

		if err := f.cidrRules.Put(&key, val); err != nil {
			return "", fmt.Errorf("put CIDR rule %s: %w", prefix.String(), err)
		}
		return prefix.String(), nil
	}

	if prefix.Addr().Is6() {
		ones := prefix.Bits()
		if ones < 0 || ones > 128 {
			return "", fmt.Errorf("invalid IPv6 prefix %s", prefix.String())
		}

		key := lpmV6Key{
			PrefixLen: uint32(ones),
			Addr:      prefix.Addr().As16(),
		}

		if err := f.cidrV6Rules.Put(&key, val); err != nil {
			return "", fmt.Errorf("put IPv6 CIDR rule %s: %w", prefix.String(), err)
		}
		return prefix.String(), nil
	}

	return "", fmt.Errorf("%s is not an IP prefix", prefix.String())
}

func (f *XDPFilter) AddIPPort(addr netip.Addr, port uint16, proto uint8) (string, error) {
	addr = addr.Unmap()
	if proto != protoTCP && proto != protoUDP {
		return "", errors.New("ip+port protocol must be tcp or udp")
	}
	val := uint32(1)

	if addr.Is4() {
		ip, err := ipv4MapUint32(addr)
		if err != nil {
			return "", err
		}

		key := ipPortKey{
			Addr:  ip,
			Port:  port,
			Proto: proto,
		}

		if err := f.ipPortRules.Put(&key, val); err != nil {
			return "", fmt.Errorf("put IP+port rule %s:%d/%s: %w", addr.String(), port, protoName(proto), err)
		}
		return fmt.Sprintf("%s:%d/%s", addr.String(), port, protoName(proto)), nil
	}

	if addr.Is6() {
		key := ipPortV6Key{
			Addr:  addr.As16(),
			Port:  port,
			Proto: proto,
		}

		if err := f.ipPortV6Rules.Put(&key, val); err != nil {
			return "", fmt.Errorf("put IPv6+port rule [%s]:%d/%s: %w", addr.String(), port, protoName(proto), err)
		}
		return fmt.Sprintf("[%s]:%d/%s", addr.String(), port, protoName(proto)), nil
	}

	return "", fmt.Errorf("%s is not an IP address", addr.String())
}

func (f *XDPFilter) GetStats() (map[string]uint64, error) {
	result := make(map[string]uint64, len(statNames))

	for i, name := range statNames {
		key := uint32(i)
		var value uint64
		if err := f.stats.Lookup(&key, &value); err != nil {
			return nil, fmt.Errorf("lookup stat %s: %w", name, err)
		}
		result[name] = value
	}

	return result, nil
}

func (f *XDPFilter) Close() error {
	if f.xdpLink != nil {
		_ = f.xdpLink.Close()
	}
	closeObjects(f.program, f.ipv4Program, f.ipv6Program, f.tcp4Program, f.udp4Program, f.tcp6Program, f.udp6Program, f.http4Program, f.tls4Program, f.http6Program, f.tls6Program, f.dns4Program, f.dns6Program, f.dispatchRules, f.scratchDomain, f.domainRules, f.cidrRules, f.cidrV6Rules, f.ipPortRules, f.ipPortV6Rules, f.stats)
	log.WithField("interface", f.iface).Info("XDP program detached")
	return nil
}

func makeDomainKey(input string) (domainKey, string, error) {
	var key domainKey

	normalized := normalizeDomain(input)
	if normalized == "" {
		return key, "", errors.New("empty domain")
	}
	if len(normalized) >= maxDomainLen {
		return key, "", fmt.Errorf("domain %q is too long (max %d)", normalized, maxDomainLen-1)
	}

	copy(key[:], normalized)
	return key, normalized, nil
}

func normalizeDomain(input string) string {
	s := strings.TrimSpace(strings.ToLower(input))
	s = strings.TrimPrefix(s, "http://")
	s = strings.TrimPrefix(s, "https://")
	if slash := strings.IndexByte(s, '/'); slash >= 0 {
		s = s[:slash]
	}
	if colon := strings.IndexByte(s, ':'); colon >= 0 {
		s = s[:colon]
	}
	return strings.TrimSuffix(s, ".")
}

func ipv4MapUint32(addr netip.Addr) (uint32, error) {
	addr = addr.Unmap()
	if !addr.Is4() {
		return 0, fmt.Errorf("%s is not an IPv4 address", addr.String())
	}

	raw := addr.As4()
	return binary.LittleEndian.Uint32(raw[:]), nil
}

func protoName(proto uint8) string {
	switch proto {
	case protoTCP:
		return "tcp"
	case protoUDP:
		return "udp"
	default:
		return fmt.Sprintf("proto%d", proto)
	}
}
