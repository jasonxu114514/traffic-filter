package main

import (
	"bytes"
	_ "embed"
	"fmt"
	"net"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	log "github.com/sirupsen/logrus"
)

//go:embed bpf/filter.bpf.o
var bpfProgram []byte

// XDPFilter manages the XDP eBPF program
type XDPFilter struct {
	program        *ebpf.Program
	blockedPorts   *ebpf.Map
	blockedDomains *ebpf.Map
	configMap      *ebpf.Map
	stats          *ebpf.Map
	xdpLink        link.Link
	iface          string
}

// NewXDPFilter creates and loads the XDP filter
func NewXDPFilter(iface string) (*XDPFilter, error) {
	// Load eBPF program from embedded bytes
	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(bpfProgram))
	if err != nil {
		return nil, fmt.Errorf("failed to load eBPF spec: %w", err)
	}

	// Load into kernel
	objs := struct {
		Program        *ebpf.Program `ebpf:"xdp_filter"`
		BlockedPorts   *ebpf.Map     `ebpf:"blocked_ports"`
		BlockedDomains *ebpf.Map     `ebpf:"blocked_domains"`
		ConfigMap      *ebpf.Map     `ebpf:"config_map"`
		Stats          *ebpf.Map     `ebpf:"stats"`
	}{}

	if err := spec.LoadAndAssign(&objs, nil); err != nil {
		return nil, fmt.Errorf("failed to load eBPF objects: %w", err)
	}

	// Initialize config map with default values
	cfgKey := uint32(0)
	cfg := struct {
		DNSMode uint32
	}{
		DNSMode: 0, // Default: DROP
	}
	if err := objs.ConfigMap.Put(&cfgKey, &cfg); err != nil {
		objs.Program.Close()
		objs.BlockedPorts.Close()
		objs.BlockedDomains.Close()
		objs.ConfigMap.Close()
		objs.Stats.Close()
		return nil, fmt.Errorf("failed to init config: %w", err)
	}

	// Get interface
	ifc, err := net.InterfaceByName(iface)
	if err != nil {
		objs.Program.Close()
		objs.BlockedPorts.Close()
		objs.Stats.Close()
		return nil, fmt.Errorf("failed to get interface %s: %w", iface, err)
	}

	// Attach XDP program
	xdpLink, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.Program,
		Interface: ifc.Index,
		Flags:     link.XDPGenericMode, // Use generic mode for compatibility
	})
	if err != nil {
		objs.Program.Close()
		objs.BlockedPorts.Close()
		objs.Stats.Close()
		return nil, fmt.Errorf("failed to attach XDP: %w", err)
	}

	log.WithField("interface", iface).Info("XDP program attached")

	return &XDPFilter{
		program:        objs.Program,
		blockedPorts:   objs.BlockedPorts,
		blockedDomains: objs.BlockedDomains,
		configMap:      objs.ConfigMap,
		stats:          objs.Stats,
		xdpLink:        xdpLink,
		iface:          iface,
	}, nil
}

// BlockPort adds a port to the blocked list
func (f *XDPFilter) BlockPort(port uint16) error {
	val := uint8(1)
	if err := f.blockedPorts.Put(port, val); err != nil {
		return fmt.Errorf("failed to block port %d: %w", port, err)
	}
	log.WithField("port", port).Debug("port blocked in XDP")
	return nil
}

// UnblockPort removes a port from the blocked list
func (f *XDPFilter) UnblockPort(port uint16) error {
	if err := f.blockedPorts.Delete(port); err != nil {
		return fmt.Errorf("failed to unblock port %d: %w", port, err)
	}
	return nil
}

// BlockDomain adds a domain to the blocked list
func (f *XDPFilter) BlockDomain(domain string) error {
	key := make([]byte, 128)
	copy(key, domain)
	val := uint8(1)
	if err := f.blockedDomains.Put(key, val); err != nil {
		return fmt.Errorf("failed to block domain %s: %w", domain, err)
	}
	log.WithField("domain", domain).Debug("domain blocked in XDP")
	return nil
}

// UnblockDomain removes a domain from the blocked list
func (f *XDPFilter) UnblockDomain(domain string) error {
	key := make([]byte, 128)
	copy(key, domain)
	if err := f.blockedDomains.Delete(key); err != nil {
		return fmt.Errorf("failed to unblock domain %s: %w", domain, err)
	}
	return nil
}

// SetDNSMode sets the DNS handling mode (0=DROP, 1=POISON)
func (f *XDPFilter) SetDNSMode(mode int) error {
	cfgKey := uint32(0)
	cfg := struct {
		DNSMode uint32
	}{
		DNSMode: uint32(mode),
	}
	if err := f.configMap.Put(&cfgKey, &cfg); err != nil {
		return fmt.Errorf("failed to set DNS mode: %w", err)
	}
	modeStr := "DROP"
	if mode == 1 {
		modeStr = "POISON"
	}
	log.WithField("mode", modeStr).Debug("DNS mode set")
	return nil
}

// GetStats returns current statistics
func (f *XDPFilter) GetStats() (total, blocked, passed uint64, err error) {
	var key uint32
	var val uint64

	key = 0 // STAT_TOTAL
	if err := f.stats.Lookup(&key, &val); err == nil {
		total = val
	}

	key = 1 // STAT_BLOCKED
	if err := f.stats.Lookup(&key, &val); err == nil {
		blocked = val
	}

	key = 2 // STAT_PASSED
	if err := f.stats.Lookup(&key, &val); err == nil {
		passed = val
	}

	return total, blocked, passed, nil
}

// GetDetailedStats returns all statistics including HTTP/TLS/DNS counts
func (f *XDPFilter) GetDetailedStats() (map[string]uint64, error) {
	stats := make(map[string]uint64)
	statNames := []string{"total", "blocked", "passed", "http", "tls", "dns", "dns_poisoned"}

	for i, name := range statNames {
		key := uint32(i)
		var val uint64
		if err := f.stats.Lookup(&key, &val); err == nil {
			stats[name] = val
		}
	}

	return stats, nil
}

// Close cleans up resources
func (f *XDPFilter) Close() error {
	if f.xdpLink != nil {
		f.xdpLink.Close()
	}
	if f.program != nil {
		f.program.Close()
	}
	if f.blockedPorts != nil {
		f.blockedPorts.Close()
	}
	if f.blockedDomains != nil {
		f.blockedDomains.Close()
	}
	if f.configMap != nil {
		f.configMap.Close()
	}
	if f.stats != nil {
		f.stats.Close()
	}
	log.Info("XDP program detached")
	return nil
}
