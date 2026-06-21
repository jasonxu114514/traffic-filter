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

const firewallComment = "middle-filter-nfqueue"

func newFirewallManager(cfg NFQueueConfig) (FirewallManager, error) {
	if !cfg.InstallRules {
		return nil, nil
	}

	backend := cfg.FirewallBackend
	switch backend {
	case "none", "disabled":
		return nil, nil
	case "auto":
		if _, err := exec.LookPath("nft"); err == nil {
			backend = "nftables"
		} else {
			backend = "iptables"
		}
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
		return iptablesFirewall{cfg: cfg}, nil
	default:
		return nil, fmt.Errorf("unknown firewall backend %q", cfg.FirewallBackend)
	}
}

type nftFirewall struct {
	cfg NFQueueConfig
}

func (f nftFirewall) Install(ctx context.Context) error {
	if err := f.Cleanup(ctx); err != nil {
		log.WithError(err).Debug("nft cleanup before install failed")
	}

	var script strings.Builder
	script.WriteString("add table inet middle_filter\n")
	for _, chain := range normalizedChains(f.cfg.Chains) {
		script.WriteString(fmt.Sprintf("add chain inet middle_filter %s { type filter hook %s priority 0; policy accept; }\n", chain, chain))
		if f.cfg.Capture == "all" {
			script.WriteString(fmt.Sprintf("add rule inet middle_filter %s queue num %d%s\n", chain, f.cfg.QueueNum, nftBypass(f.cfg.FailOpen)))
			continue
		}
		script.WriteString(fmt.Sprintf("add rule inet middle_filter %s tcp dport { 80, 443 } queue num %d%s\n", chain, f.cfg.QueueNum, nftBypass(f.cfg.FailOpen)))
		script.WriteString(fmt.Sprintf("add rule inet middle_filter %s udp dport 53 queue num %d%s\n", chain, f.cfg.QueueNum, nftBypass(f.cfg.FailOpen)))
	}

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
	cfg NFQueueConfig
}

func (f iptablesFirewall) Install(ctx context.Context) error {
	if err := f.Cleanup(ctx); err != nil {
		log.WithError(err).Debug("iptables cleanup before install failed")
	}
	for _, bin := range []string{"iptables", "ip6tables"} {
		if _, err := exec.LookPath(bin); err != nil {
			if bin == "ip6tables" {
				log.WithError(err).Warn("ip6tables not found; IPv6 firewall rules were not installed")
				continue
			}
			return err
		}
		for _, chain := range normalizedChains(f.cfg.Chains) {
			if f.cfg.Capture == "all" {
				if err := runCommand(ctx, bin, append([]string{"-I", strings.ToUpper(chain)}, f.commonArgs()...), false); err != nil {
					return err
				}
				continue
			}
			if err := runCommand(ctx, bin, append([]string{"-I", strings.ToUpper(chain), "-p", "tcp", "-m", "multiport", "--dports", "80,443"}, f.commonArgs()...), false); err != nil {
				return err
			}
			if err := runCommand(ctx, bin, append([]string{"-I", strings.ToUpper(chain), "-p", "udp", "--dport", "53"}, f.commonArgs()...), false); err != nil {
				return err
			}
		}
	}
	return nil
}

func (f iptablesFirewall) Cleanup(ctx context.Context) error {
	for _, bin := range []string{"iptables", "ip6tables"} {
		if _, err := exec.LookPath(bin); err != nil {
			continue
		}
		for _, chain := range normalizedChains(f.cfg.Chains) {
			if f.cfg.Capture == "all" {
				_ = runCommand(ctx, bin, append([]string{"-D", strings.ToUpper(chain)}, f.commonArgs()...), true)
				continue
			}
			_ = runCommand(ctx, bin, append([]string{"-D", strings.ToUpper(chain), "-p", "tcp", "-m", "multiport", "--dports", "80,443"}, f.commonArgs()...), true)
			_ = runCommand(ctx, bin, append([]string{"-D", strings.ToUpper(chain), "-p", "udp", "--dport", "53"}, f.commonArgs()...), true)
		}
	}
	return nil
}

func (f iptablesFirewall) commonArgs() []string {
	args := []string{
		"-m", "comment", "--comment", firewallComment,
		"-j", "NFQUEUE", "--queue-num", fmt.Sprintf("%d", f.cfg.QueueNum),
	}
	if f.cfg.FailOpen {
		args = append(args, "--queue-bypass")
	}
	return args
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
