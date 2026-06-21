package filter

import (
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	log "github.com/sirupsen/logrus"

	"github.com/traffic-filter/pkg/config"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang-14 -cflags "-O2 -g -Wall" bpf ../../bpf/traffic_filter.c -- -I/usr/include -I/usr/include/x86_64-linux-gnu

// Stat indices matching the eBPF enum.
const (
	StatTotalPackets   = 0
	StatBlockedPackets = 1
	StatHTTPPackets    = 2
	StatTLSPackets     = 3
	StatDNSPackets     = 4
	StatIPBlocked      = 5
	StatIPPortBlocked  = 6
	StatRSTSent        = 7
)

// EbpfConfig matches the C struct config.
type EbpfConfig struct {
	DNSMode   uint32
	IPMode    uint32
	IPPortMask uint32
}

// TrafficFilter manages the eBPF/XDP program lifecycle.
type TrafficFilter struct {
	objs    *bpfObjects
	xdpLink link.Link
	cfg     *config.Config
}

// New creates and attaches an XDP filter.
func New(cfg *config.Config) (*TrafficFilter, error) {
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("remove memlock: %w", err)
	}

	objs := &bpfObjects{}
	if err := loadBpfObjects(objs, nil); err != nil {
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			log.Errorf("BPF verifier error: %+v", ve)
		}
		return nil, fmt.Errorf("load BPF objects: %w", err)
	}

	ifaceIdx, err := getIfIndex(cfg.Interface)
	if err != nil {
		objs.Close()
		return nil, err
	}

	xdpLink, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.XdpFilter,
		Interface: ifaceIdx,
		Flags:     link.XDPGenericMode,
	})
	if err != nil {
		objs.Close()
		return nil, fmt.Errorf("attach XDP: %w", err)
	}

	tf := &TrafficFilter{
		objs:    objs,
		xdpLink: xdpLink,
		cfg:     cfg,
	}

	if err := tf.initConfig(); err != nil {
		tf.Close()
		return nil, fmt.Errorf("init config: %w", err)
	}
	if err := tf.initStats(); err != nil {
		tf.Close()
		return nil, fmt.Errorf("init stats: %w", err)
	}
	if err := tf.populateBlockedDomains(); err != nil {
		tf.Close()
		return nil, fmt.Errorf("populate domains: %w", err)
	}
	if err := tf.populateBlockedIPs(); err != nil {
		tf.Close()
		return nil, fmt.Errorf("populate IPs: %w", err)
	}
	if err := tf.populateBlockedIPPorts(); err != nil {
		tf.Close()
		return nil, fmt.Errorf("populate IP:Ports: %w", err)
	}

	log.WithField("iface", cfg.Interface).Info("XDP program attached")
	return tf, nil
}

// Close detaches and cleans up all eBPF resources.
func (tf *TrafficFilter) Close() {
	if tf.xdpLink != nil {
		tf.xdpLink.Close()
	}
	if tf.objs != nil {
		tf.objs.Close()
	}
	log.Info("filter shutdown complete")
}

// ─── init helpers ─────────────────────────────────────────────────────────

func (tf *TrafficFilter) initConfig() error {
	k := uint32(0)
	ec := EbpfConfig{
		DNSMode:    uint32(tf.cfg.DNSMode),
		IPMode:     uint32(tf.cfg.IPMode),
		IPPortMask: uint32(tf.cfg.IPPortMode),
	}
	if err := tf.objs.ConfigMap.Put(&k, &ec); err != nil {
		return fmt.Errorf("put config: %w", err)
	}
	log.WithFields(log.Fields{
		"dns_mode":     tf.cfg.DNSMode,
		"ip_mode":      fmt.Sprintf("%03b", tf.cfg.IPMode),
		"ip_port_mask": fmt.Sprintf("%03b", tf.cfg.IPPortMode),
	}).Info("eBPF config set")
	return nil
}

func (tf *TrafficFilter) initStats() error {
	zero := uint64(0)
	for i := uint32(0); i < 8; i++ {
		if err := tf.objs.Stats.Put(&i, &zero); err != nil {
			return err
		}
	}
	return nil
}

func (tf *TrafficFilter) populateBlockedDomains() error {
	one := uint32(1)
	for _, d := range tf.cfg.Domains {
		key := make([]byte, 128)
		copy(key, d)
		if err := tf.objs.BlockedDomains.Put(key, &one); err != nil {
			return fmt.Errorf("domain %s: %w", d, err)
		}
		log.WithField("domain", d).Info("blocked domain added")
	}
	return nil
}

func (tf *TrafficFilter) populateBlockedIPs() error {
	one := uint32(1)
	for _, ip := range tf.cfg.IPs {
		if err := tf.objs.BlockedIps.Put(&ip, &one); err != nil {
			return fmt.Errorf("IP %08x: %w", ip, err)
		}
		log.WithField("ip", fmt.Sprintf("%08x", ip)).Info("blocked IP added")
	}
	return nil
}

func (tf *TrafficFilter) populateBlockedIPPorts() error {
	one := uint32(1)
	for _, e := range tf.cfg.IPPorts {
		key := struct {
			IP    uint32
			Port  uint16
			Proto uint8
			Pad   uint8
		}{
			IP:    e.IP,
			Port:  e.Port,
			Proto: e.Proto,
		}
		if err := tf.objs.BlockedIpPorts.Put(&key, &one); err != nil {
			return fmt.Errorf("IP:Port %08x:%d/%d: %w", e.IP, e.Port, e.Proto, err)
		}
		log.WithField("entry", fmt.Sprintf("%08x:%d/%d", e.IP, e.Port, e.Proto)).
			Info("blocked IP:Port added")
	}
	return nil
}

// ─── statistics ──────────────────────────────────────────────────────────

// RunStatsMonitor prints per-second statistics every interval.
func (tf *TrafficFilter) RunStatsMonitor(interval time.Duration, stop <-chan struct{}) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	var prev [8]uint64

	for {
		select {
		case <-stop:
			return
		case <-ticker.C:
			cur := [8]uint64{}
			for i := uint32(0); i < 8; i++ {
				v, _ := tf.getStat(i)
				cur[i] = v
			}

			sec := uint64(interval.Seconds())
			log.WithFields(log.Fields{
				"total":        cur[0],
				"blocked":      cur[1],
				"http":         cur[2],
				"tls":          cur[3],
				"dns":          cur[4],
				"ip_blocked":   cur[5],
				"ip_port_blk":  cur[6],
				"rst_sent":     cur[7],
				"total/s":      (cur[0] - prev[0]) / sec,
				"blocked/s":    (cur[1] - prev[1]) / sec,
				"http/s":       (cur[2] - prev[2]) / sec,
				"tls/s":        (cur[3] - prev[3]) / sec,
				"dns/s":        (cur[4] - prev[4]) / sec,
				"ip_blk/s":     (cur[5] - prev[5]) / sec,
				"ip_port_blk/s": (cur[6] - prev[6]) / sec,
				"rst/s":        (cur[7] - prev[7]) / sec,
			}).Info("stats")

			prev = cur
		}
	}
}

func (tf *TrafficFilter) getStat(key uint32) (uint64, error) {
	var v uint64
	if err := tf.objs.Stats.Lookup(&key, &v); err != nil {
		return 0, err
	}
	return v, nil
}

func getIfIndex(name string) (int, error) {
	data, err := os.ReadFile(fmt.Sprintf("/sys/class/net/%s/ifindex", name))
	if err != nil {
		return 0, fmt.Errorf("interface %s not found: %w", name, err)
	}
	var idx int
	fmt.Sscanf(string(data), "%d", &idx)
	return idx, nil
}
