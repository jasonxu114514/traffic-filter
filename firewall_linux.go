//go:build linux

package main

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strings"

	log "github.com/sirupsen/logrus"
)

func newFirewallManager(cfg NFQueueConfig) (FirewallManager, error) {
	if !cfg.InstallRules {
		return nil, nil
	}

	backend := cfg.FirewallBackend
	switch backend {
	case "none", "disabled":
		return nil, nil
	case "auto":
		var candidates []FirewallManager
		if _, err := exec.LookPath("nft"); err == nil {
			candidates = append(candidates, nftFirewall{cfg: cfg})
		}
		if _, err := exec.LookPath("iptables"); err == nil {
			candidates = append(candidates, iptablesFirewall{
				cfg:     cfg,
				ipv4Bin: "iptables",
				ipv6Bin: "ip6tables",
				label:   "iptables",
			})
		}
		if _, err := exec.LookPath("iptables-legacy"); err == nil {
			candidates = append(candidates, iptablesFirewall{
				cfg:     cfg,
				ipv4Bin: "iptables-legacy",
				ipv6Bin: "ip6tables-legacy",
				label:   "iptables-legacy",
			})
		}
		if len(candidates) == 0 {
			return nil, fmt.Errorf("firewall_backend auto found neither nft nor iptables")
		}
		return &autoFirewall{candidates: candidates}, nil
	case "nft":
		backend = "nftables"
	}

	switch backend {
	case "nftables":
		if _, err := exec.LookPath("nft"); err != nil {
			return nil, fmt.Errorf("nftables backend selected but nft was not found: %w", err)
		}
		return nftFirewall{cfg: cfg}, nil
	case "iptables":
		if _, err := exec.LookPath("iptables"); err != nil {
			return nil, fmt.Errorf("iptables backend selected but iptables was not found: %w", err)
		}
		return iptablesFirewall{
			cfg:     cfg,
			ipv4Bin: "iptables",
			ipv6Bin: "ip6tables",
			label:   "iptables",
		}, nil
	case "iptables-legacy":
		if _, err := exec.LookPath("iptables-legacy"); err != nil {
			return nil, fmt.Errorf("iptables-legacy backend selected but iptables-legacy was not found: %w", err)
		}
		return iptablesFirewall{
			cfg:     cfg,
			ipv4Bin: "iptables-legacy",
			ipv6Bin: "ip6tables-legacy",
			label:   "iptables-legacy",
		}, nil
	default:
		return nil, fmt.Errorf("unknown firewall backend %q", cfg.FirewallBackend)
	}
}

type autoFirewall struct {
	candidates []FirewallManager
	active     FirewallManager
}

func (f *autoFirewall) Install(ctx context.Context) error {
	var errs []string
	for _, candidate := range f.candidates {
		if err := candidate.Install(ctx); err != nil {
			errs = append(errs, err.Error())
			log.WithError(err).Warn("firewall backend failed; trying next backend")
			_ = candidate.Cleanup(context.Background())
			continue
		}
		f.active = candidate
		return nil
	}
	return fmt.Errorf("all firewall backends failed: %s", strings.Join(errs, "; "))
}

func explainNFQueueFirewallError(err error) error {
	msg := err.Error()
	lower := strings.ToLower(msg)
	missingNFQueue := strings.Contains(lower, "nfqueue revision 0 not supported") ||
		strings.Contains(lower, "nfnetlink_queue") ||
		strings.Contains(lower, "xt_nfqueue") ||
		(strings.Contains(lower, "queue num") && strings.Contains(lower, "no such file or directory")) ||
		(strings.Contains(lower, "-j nfqueue") && strings.Contains(lower, "no such file or directory"))
	if !missingNFQueue {
		return err
	}

	return fmt.Errorf("%w; kernel NFQUEUE support appears unavailable. This engine requires CONFIG_NETFILTER_NETLINK_QUEUE plus nft_queue or xt_NFQUEUE support. Use a kernel/VPS image that provides nfnetlink_queue/xt_NFQUEUE, or switch to a non-NFQUEUE engine such as a future TUN/AF_XDP path", err)
}

func (f *autoFirewall) Cleanup(ctx context.Context) error {
	for _, candidate := range f.candidates {
		_ = candidate.Cleanup(ctx)
	}
	f.active = nil
	return nil
}

type nftFirewall struct {
	cfg NFQueueConfig
}

func (f nftFirewall) Install(ctx context.Context) error {
	ensureNFQueueKernelSupport(ctx)

	if err := f.Cleanup(ctx); err != nil {
		log.WithError(err).Debug("nft cleanup before install failed")
	}

	var script strings.Builder
	script.WriteString("table inet middle_filter {\n")
	for _, chain := range normalizedChains(f.cfg.Chains) {
		script.WriteString(fmt.Sprintf("  chain %s {\n", chain))
		script.WriteString(fmt.Sprintf("    type filter hook %s priority 0; policy accept;\n", chain))
		if f.cfg.Capture == "all" {
			script.WriteString(fmt.Sprintf("    queue num %d%s\n", f.cfg.QueueNum, nftBypass(f.cfg.FailOpen)))
			script.WriteString("  }\n")
			continue
		}
		script.WriteString(fmt.Sprintf("    tcp dport { 80, 443 } queue num %d%s\n", f.cfg.QueueNum, nftBypass(f.cfg.FailOpen)))
		script.WriteString(fmt.Sprintf("    udp dport 53 queue num %d%s\n", f.cfg.QueueNum, nftBypass(f.cfg.FailOpen)))
		script.WriteString("  }\n")
	}
	script.WriteString("}\n")

	if err := runWithInput(ctx, "nft", []string{"-f", "-"}, script.String(), false); err != nil {
		return fmt.Errorf("install nftables rules: %w", err)
	}
	return nil
}

func (f nftFirewall) Cleanup(ctx context.Context) error {
	return runWithInput(ctx, "nft", []string{"delete", "table", "inet", "middle_filter"}, "", true)
}

func nftBypass(failOpen bool) string {
	if failOpen {
		return " bypass"
	}
	return ""
}

type iptablesFirewall struct {
	cfg     NFQueueConfig
	ipv4Bin string
	ipv6Bin string
	label   string
}

func (f iptablesFirewall) Install(ctx context.Context) error {
	ensureNFQueueKernelSupport(ctx)

	if err := f.Cleanup(ctx); err != nil {
		log.WithError(err).Debug("iptables cleanup before install failed")
	}
	for _, bin := range []string{f.ipv4Bin, f.ipv6Bin} {
		if _, err := exec.LookPath(bin); err != nil {
			if bin == f.ipv6Bin {
				log.WithError(err).WithField("backend", f.label).Warn("IPv6 iptables binary not found; IPv6 firewall rules were not installed")
				continue
			}
			return err
		}
		for _, chain := range normalizedChains(f.cfg.Chains) {
			if f.cfg.Capture == "all" {
				if err := runCommand(ctx, bin, append([]string{"-I", strings.ToUpper(chain)}, f.queueArgs()...), false); err != nil {
					return err
				}
				continue
			}
			for _, port := range []string{"80", "443"} {
				if err := runCommand(ctx, bin, append([]string{"-I", strings.ToUpper(chain), "-p", "tcp", "--dport", port}, f.queueArgs()...), false); err != nil {
					return err
				}
			}
			if err := runCommand(ctx, bin, append([]string{"-I", strings.ToUpper(chain), "-p", "udp", "--dport", "53"}, f.queueArgs()...), false); err != nil {
				return err
			}
		}
	}
	return nil
}

func (f iptablesFirewall) Cleanup(ctx context.Context) error {
	for _, bin := range []string{f.ipv4Bin, f.ipv6Bin} {
		if _, err := exec.LookPath(bin); err != nil {
			continue
		}
		for _, chain := range normalizedChains(f.cfg.Chains) {
			if f.cfg.Capture == "all" {
				deleteIPTablesRule(ctx, bin, append([]string{"-D", strings.ToUpper(chain)}, f.queueArgs()...))
				continue
			}
			for _, port := range []string{"80", "443"} {
				deleteIPTablesRule(ctx, bin, append([]string{"-D", strings.ToUpper(chain), "-p", "tcp", "--dport", port}, f.queueArgs()...))
			}
			deleteIPTablesRule(ctx, bin, append([]string{"-D", strings.ToUpper(chain), "-p", "udp", "--dport", "53"}, f.queueArgs()...))
		}
	}
	return nil
}

func (f iptablesFirewall) queueArgs() []string {
	args := []string{
		"-j", "NFQUEUE", "--queue-num", fmt.Sprintf("%d", f.cfg.QueueNum),
	}
	if f.cfg.FailOpen {
		args = append(args, "--queue-bypass")
	}
	return args
}

func deleteIPTablesRule(ctx context.Context, bin string, args []string) {
	for i := 0; i < 20; i++ {
		if err := runCommand(ctx, bin, args, false); err != nil {
			return
		}
	}
}

func normalizedChains(raw []string) []string {
	out := make([]string, 0, len(raw))
	seen := make(map[string]struct{}, len(raw))
	for _, chain := range raw {
		chain = normalizeChoice(chain, "")
		if chain == "" {
			continue
		}
		if _, ok := seen[chain]; ok {
			continue
		}
		seen[chain] = struct{}{}
		out = append(out, chain)
	}
	return out
}

func runCommand(ctx context.Context, name string, args []string, ignoreError bool) error {
	return runWithInput(ctx, name, args, "", ignoreError)
}

func runWithInput(ctx context.Context, name string, args []string, stdin string, ignoreError bool) error {
	cmd := exec.CommandContext(ctx, name, args...)
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	err := cmd.Run()
	if err != nil {
		if ignoreError {
			return nil
		}
		msg := strings.TrimSpace(stderr.String())
		if msg != "" {
			return fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "), err, msg)
		}
		return fmt.Errorf("%s %s: %w", name, strings.Join(args, " "), err)
	}
	return nil
}

func ensureNFQueueKernelSupport(ctx context.Context) {
	if _, err := exec.LookPath("modprobe"); err != nil {
		return
	}
	for _, module := range []string{"nfnetlink_queue", "nft_queue", "xt_NFQUEUE"} {
		if err := runCommand(ctx, "modprobe", []string{module}, true); err != nil {
			log.WithError(err).WithField("module", module).Debug("modprobe failed")
		}
	}
}
