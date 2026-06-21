//go:build linux

package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/netip"
	"os"
	"sync/atomic"
	"syscall"
	"time"

	nfqueue "github.com/florianl/go-nfqueue"
	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

type nfQueueEngine struct {
	cfg        AppConfig
	rules      RuleSet
	classifier packetClassifier
	firewall   FirewallManager
	nfq        *nfqueue.Nfqueue
	stats      atomicStats
}

type atomicStats struct {
	total         atomic.Uint64
	passed        atomic.Uint64
	httpBlocked   atomic.Uint64
	tlsBlocked    atomic.Uint64
	dnsPoisoned   atomic.Uint64
	dnsBlocked    atomic.Uint64
	ipBlocked     atomic.Uint64
	ipPortBlocked atomic.Uint64
	malformed     atomic.Uint64
}

func newNFQueueEngine(cfg AppConfig) (Engine, error) {
	rules, err := compileRuleSet(cfg.Rules)
	if err != nil {
		return nil, err
	}

	firewall, err := newFirewallManager(cfg.NFQueue)
	if err != nil {
		return nil, err
	}

	return &nfQueueEngine{
		cfg:        cfg,
		rules:      rules,
		classifier: newPacketClassifier(rules, cfg.NFQueue.DNSMode),
		firewall:   firewall,
	}, nil
}

func (e *nfQueueEngine) Run(ctx context.Context) error {
	if e.firewall != nil {
		if err := e.firewall.Install(ctx); err != nil {
			return err
		}
		defer func() {
			if err := e.firewall.Cleanup(context.Background()); err != nil {
				log.Printf("failed to cleanup firewall rules: %v", err)
			}
		}()
	}

	flags := uint32(0)
	if e.cfg.NFQueue.FailOpen {
		flags |= nfqueue.NfQaCfgFlagFailOpen
	}

	nfq, err := nfqueue.Open(&nfqueue.Config{
		NfQueue:      e.cfg.NFQueue.QueueNum,
		MaxPacketLen: 0xffff,
		MaxQueueLen:  0x400,
		Copymode:     nfqueue.NfQnlCopyPacket,
		Flags:        flags,
		AfFamily:     uint8(unix.AF_UNSPEC),
		WriteTimeout: 50 * time.Millisecond,
		Logger:       log.New(os.Stderr, "nfqueue: ", log.LstdFlags),
	})
	if err != nil {
		return fmt.Errorf("open nfqueue %d: %w", e.cfg.NFQueue.QueueNum, err)
	}
	e.nfq = nfq
	defer nfq.Close()

	if err := nfq.SetOption(netlink.NoENOBUFS, true); err != nil {
		return fmt.Errorf("set nfqueue NoENOBUFS: %w", err)
	}

	if err := nfq.RegisterWithErrorFunc(ctx, e.handlePacket, func(err error) int {
		if ctx.Err() != nil {
			return 0
		}
		log.Printf("nfqueue receive error: %v", err)
		return 0
	}); err != nil {
		return fmt.Errorf("register nfqueue callback: %w", err)
	}

	<-ctx.Done()
	return nil
}

func (e *nfQueueEngine) Close() error {
	if e.nfq != nil {
		return e.nfq.Close()
	}
	return nil
}

func (e *nfQueueEngine) Stats() EngineStats {
	return EngineStats{
		Total:         e.stats.total.Load(),
		Passed:        e.stats.passed.Load(),
		HTTPBlocked:   e.stats.httpBlocked.Load(),
		TLSBlocked:    e.stats.tlsBlocked.Load(),
		DNSPoisoned:   e.stats.dnsPoisoned.Load(),
		DNSBlocked:    e.stats.dnsBlocked.Load(),
		IPBlocked:     e.stats.ipBlocked.Load(),
		IPPortBlocked: e.stats.ipPortBlocked.Load(),
		Malformed:     e.stats.malformed.Load(),
	}
}

func (e *nfQueueEngine) handlePacket(attr nfqueue.Attribute) int {
	if attr.PacketID == nil {
		e.stats.malformed.Add(1)
		return 0
	}

	id := *attr.PacketID
	if attr.Payload == nil {
		e.stats.malformed.Add(1)
		_ = e.nfq.SetVerdict(id, nfqueue.NfAccept)
		return 0
	}

	e.stats.total.Add(1)
	decision := e.classifier.Classify(*attr.Payload)
	e.recordDecision(decision)

	switch decision.Kind {
	case verdictDrop:
		if decision.DNSResponse != nil {
			if err := sendDNSResponse(*decision.DNSResponse); err != nil && e.cfg.Debug {
				log.Printf("failed to send DNS response: %v", err)
			}
		}
		_ = e.nfq.SetVerdict(id, nfqueue.NfDrop)
	default:
		_ = e.nfq.SetVerdict(id, nfqueue.NfAccept)
	}

	return 0
}

func (e *nfQueueEngine) recordDecision(decision packetVerdict) {
	switch decision.Reason {
	case reasonHTTP:
		e.stats.httpBlocked.Add(1)
	case reasonTLS:
		e.stats.tlsBlocked.Add(1)
	case reasonDNSPoison:
		e.stats.dnsPoisoned.Add(1)
	case reasonDNSDrop:
		e.stats.dnsBlocked.Add(1)
	case reasonIP:
		e.stats.ipBlocked.Add(1)
	case reasonIPPort:
		e.stats.ipPortBlocked.Add(1)
	case reasonMalformed:
		e.stats.malformed.Add(1)
	}

	if decision.Kind == verdictAccept {
		e.stats.passed.Add(1)
	}
}

func sendDNSResponse(resp dnsResponse) error {
	if len(resp.Payload) == 0 {
		return fmt.Errorf("empty DNS response")
	}
	if resp.SrcIP.Is4() != resp.DstIP.Is4() {
		return fmt.Errorf("DNS response address family mismatch: %s -> %s", resp.SrcIP, resp.DstIP)
	}

	network := "udp6"
	if resp.SrcIP.Is4() {
		network = "udp4"
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	lc := net.ListenConfig{
		Control: func(network, address string, c syscall.RawConn) error {
			var controlErr error
			if err := c.Control(func(fd uintptr) {
				if resp.SrcIP.Is4() {
					controlErr = unix.SetsockoptInt(int(fd), unix.SOL_IP, unix.IP_FREEBIND, 1)
					return
				}
				controlErr = unix.SetsockoptInt(int(fd), unix.SOL_IPV6, unix.IPV6_FREEBIND, 1)
			}); err != nil {
				return err
			}
			return controlErr
		},
	}

	conn, err := lc.ListenPacket(ctx, network, (&net.UDPAddr{
		IP:   netIPFromAddr(resp.SrcIP),
		Port: int(resp.SrcPort),
	}).String())
	if err != nil {
		return err
	}
	defer conn.Close()

	_, err = conn.WriteTo(resp.Payload, &net.UDPAddr{
		IP:   netIPFromAddr(resp.DstIP),
		Port: int(resp.DstPort),
	})
	return err
}

func netIPFromAddr(addr netip.Addr) net.IP {
	addr = addr.Unmap()
	if addr.Is4() {
		v4 := addr.As4()
		return net.IPv4(v4[0], v4[1], v4[2], v4[3])
	}
	v6 := addr.As16()
	return append(net.IP(nil), v6[:]...)
}
