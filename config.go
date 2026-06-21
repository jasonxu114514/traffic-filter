package main

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"strings"
	"time"
)

const (
	defaultEngine        = "nfqueue"
	defaultStatsInterval = 5 * time.Second
	defaultQueueNum      = 100
	defaultFirewall      = "auto"
	defaultCapture       = "l7"
	defaultDNSMode       = "nxdomain"
)

type AppConfig struct {
	Engine        string        `json:"engine"`
	Debug         bool          `json:"debug"`
	StatsInterval string        `json:"stats_interval"`
	Rules         RuleConfig    `json:"rules"`
	NFQueue       NFQueueConfig `json:"nfqueue"`
	AFXDP         AFXDPConfig   `json:"af_xdp"`
	statsEvery    time.Duration `json:"-"`
}

type RuleConfig struct {
	Domains          []string           `json:"domains"`
	DNSPoisonDomains []string           `json:"dns_poison_domains"`
	IPs              []string           `json:"ips"`
	IPPorts          []IPPortRuleConfig `json:"ip_ports"`
}

type IPPortRuleConfig struct {
	IP    string `json:"ip"`
	Port  uint16 `json:"port"`
	Proto string `json:"proto"`
}

type NFQueueConfig struct {
	QueueNum        uint16   `json:"queue_num"`
	FirewallBackend string   `json:"firewall_backend"`
	InstallRules    bool     `json:"install_rules"`
	Chains          []string `json:"chains"`
	Capture         string   `json:"capture"`
	FailOpen        bool     `json:"fail_open"`
	DNSMode         string   `json:"dns_mode"`
}

type AFXDPConfig struct {
	Iface string `json:"iface"`
	Mode  string `json:"mode"`
}

func loadConfig(path string) (AppConfig, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		path = defaultConfigPath
	}

	file, err := os.Open(path)
	if err != nil {
		return AppConfig{}, fmt.Errorf("open config %s: %w", path, err)
	}
	defer file.Close()

	cfg := AppConfig{
		Engine:     defaultEngine,
		statsEvery: defaultStatsInterval,
		NFQueue: NFQueueConfig{
			QueueNum:        defaultQueueNum,
			FirewallBackend: defaultFirewall,
			InstallRules:    true,
			Chains:          []string{"input", "output", "forward"},
			Capture:         defaultCapture,
			DNSMode:         defaultDNSMode,
		},
	}

	decoder := json.NewDecoder(file)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&cfg); err != nil {
		return AppConfig{}, fmt.Errorf("decode config %s: %w", path, err)
	}

	cfg.Engine = normalizeChoice(cfg.Engine, defaultEngine)
	switch cfg.Engine {
	case "nfqueue", "af_xdp", "xdp_fast_path":
	default:
		return AppConfig{}, fmt.Errorf("invalid engine %q", cfg.Engine)
	}

	if strings.TrimSpace(cfg.StatsInterval) != "" {
		interval, err := time.ParseDuration(strings.TrimSpace(cfg.StatsInterval))
		if err != nil {
			return AppConfig{}, fmt.Errorf("invalid stats_interval: %w", err)
		}
		cfg.statsEvery = interval
	}
	if cfg.statsEvery <= 0 {
		return AppConfig{}, fmt.Errorf("invalid stats_interval: must be positive")
	}

	if cfg.NFQueue.QueueNum == 0 {
		cfg.NFQueue.QueueNum = defaultQueueNum
	}
	cfg.NFQueue.FirewallBackend = normalizeChoice(cfg.NFQueue.FirewallBackend, defaultFirewall)
	cfg.NFQueue.Capture = normalizeChoice(cfg.NFQueue.Capture, defaultCapture)
	cfg.NFQueue.DNSMode = normalizeChoice(cfg.NFQueue.DNSMode, defaultDNSMode)
	if len(cfg.NFQueue.Chains) == 0 {
		cfg.NFQueue.Chains = []string{"input", "output", "forward"}
	}
	if err := validateNFQueueConfig(cfg.NFQueue); err != nil {
		return AppConfig{}, err
	}

	if _, err := compileRuleSet(cfg.Rules); err != nil {
		return AppConfig{}, err
	}

	return cfg, nil
}

func validateNFQueueConfig(cfg NFQueueConfig) error {
	switch cfg.FirewallBackend {
	case "auto", "nftables", "nft", "iptables", "none", "disabled":
	default:
		return fmt.Errorf("invalid nfqueue.firewall_backend %q", cfg.FirewallBackend)
	}

	switch cfg.Capture {
	case "l7", "all":
	default:
		return fmt.Errorf("invalid nfqueue.capture %q", cfg.Capture)
	}

	switch cfg.DNSMode {
	case "nxdomain", "drop":
	default:
		return fmt.Errorf("invalid nfqueue.dns_mode %q", cfg.DNSMode)
	}

	for _, chain := range cfg.Chains {
		switch normalizeChoice(chain, "") {
		case "input", "output", "forward":
		default:
			return fmt.Errorf("invalid nfqueue chain %q", chain)
		}
	}

	return nil
}

func normalizeChoice(raw, fallback string) string {
	raw = strings.ToLower(strings.TrimSpace(raw))
	if raw == "" {
		return fallback
	}
	return raw
}

func parseIPPrefix(raw string) (netip.Prefix, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return netip.Prefix{}, fmt.Errorf("empty IP/CIDR rule")
	}

	if strings.Contains(raw, "/") {
		prefix, err := netip.ParsePrefix(raw)
		if err != nil {
			return netip.Prefix{}, err
		}
		addr := prefix.Addr().Unmap()
		if !addr.Is4() && !addr.Is6() {
			return netip.Prefix{}, fmt.Errorf("%s is not an IP address", raw)
		}
		if addr != prefix.Addr() {
			return netip.Prefix{}, fmt.Errorf("%s uses IPv4-mapped IPv6 CIDR; use an IPv4 CIDR instead", raw)
		}
		return prefix.Masked(), nil
	}

	addr, err := netip.ParseAddr(raw)
	if err != nil {
		return netip.Prefix{}, err
	}
	addr = addr.Unmap()
	if addr.Is4() {
		return netip.PrefixFrom(addr, 32), nil
	}
	if addr.Is6() {
		return netip.PrefixFrom(addr, 128), nil
	}
	return netip.Prefix{}, fmt.Errorf("%s is not an IP address", raw)
}

func parseProto(raw string) (uint8, error) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "", "tcp":
		return protoTCP, nil
	case "udp":
		return protoUDP, nil
	default:
		return 0, fmt.Errorf("invalid protocol %q (use tcp or udp)", raw)
	}
}
