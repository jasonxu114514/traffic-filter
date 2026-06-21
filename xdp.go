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
	program      *ebpf.Program
	blockedPorts *ebpf.Map
	stats        *ebpf.Map
	xdpLink      link.Link
	iface        string
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
		Program      *ebpf.Program `ebpf:"xdp_filter"`
		BlockedPorts *ebpf.Map     `ebpf:"blocked_ports"`
		Stats        *ebpf.Map     `ebpf:"stats"`
	}{}

	if err := spec.LoadAndAssign(&objs, nil); err != nil {
		return nil, fmt.Errorf("failed to load eBPF objects: %w", err)
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
		program:      objs.Program,
		blockedPorts: objs.BlockedPorts,
		stats:        objs.Stats,
		xdpLink:      xdpLink,
		iface:        iface,
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
	if f.stats != nil {
		f.stats.Close()
	}
	log.Info("XDP program detached")
	return nil
}
