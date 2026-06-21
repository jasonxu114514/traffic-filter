package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"net/netip"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	log "github.com/sirupsen/logrus"
)

const (
	defaultConfigPath    = "config.json"
	defaultXDPMode       = "generic"
	defaultStatsInterval = 5 * time.Second
)

type AppConfig struct {
	Iface         string        `json:"iface"`
	XDPMode       string        `json:"xdp_mode"`
	Debug         bool          `json:"debug"`
	StatsInterval string        `json:"stats_interval"`
	Rules         RuleConfig    `json:"rules"`
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

func main() {
	if err := run(); err != nil {
		log.WithError(err).Fatal("middle filter failed")
	}
}

func run() error {
	configPath := flag.String("config", defaultConfigPath, "path to JSON config file")
	flag.Parse()

	if flag.NArg() != 0 {
		return fmt.Errorf("unexpected positional arguments: %s", strings.Join(flag.Args(), " "))
	}

	cfg, err := loadConfig(*configPath)
	if err != nil {
		return err
	}

	if cfg.Debug {
		log.SetLevel(log.DebugLevel)
	} else {
		log.SetLevel(log.InfoLevel)
	}

	if os.Geteuid() != 0 {
		return fmt.Errorf("this program must run as root")
	}

	filter, err := NewXDPFilter(cfg.Iface, cfg.XDPMode)
	if err != nil {
		return fmt.Errorf("start XDP filter: %w", err)
	}
	defer filter.Close()

	if err := loadDomainRules(filter, cfg.Rules.Domains, domainHTTP|domainTLS, "http/tls"); err != nil {
		return fmt.Errorf("load domain rules: %w", err)
	}
	if err := loadDomainRules(filter, cfg.Rules.DNSPoisonDomains, domainDNSPoison, "dns-poison"); err != nil {
		return fmt.Errorf("load DNS poison rules: %w", err)
	}
	if err := loadCIDRRules(filter, cfg.Rules.IPs); err != nil {
		return fmt.Errorf("load IP/CIDR rules: %w", err)
	}
	if err := loadIPPortRules(filter, cfg.Rules.IPPorts); err != nil {
		return fmt.Errorf("load IP+port rules: %w", err)
	}

	log.Info("middle filter active; press Ctrl+C to stop")

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)

	ticker := time.NewTicker(cfg.statsEvery)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			printStats(filter)
		case <-stop:
			log.Info("shutting down")
			printStats(filter)
			return nil
		}
	}
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
		XDPMode:    defaultXDPMode,
		statsEvery: defaultStatsInterval,
	}

	decoder := json.NewDecoder(file)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&cfg); err != nil {
		return AppConfig{}, fmt.Errorf("decode config %s: %w", path, err)
	}

	if strings.TrimSpace(cfg.Iface) == "" {
		return AppConfig{}, fmt.Errorf("config iface is required")
	}
	cfg.Iface = strings.TrimSpace(cfg.Iface)

	cfg.XDPMode = strings.TrimSpace(cfg.XDPMode)
	if cfg.XDPMode == "" {
		cfg.XDPMode = defaultXDPMode
	}
	if _, err := xdpAttachFlags(cfg.XDPMode); err != nil {
		return AppConfig{}, err
	}

	if strings.TrimSpace(cfg.StatsInterval) != "" {
		interval, err := time.ParseDuration(strings.TrimSpace(cfg.StatsInterval))
		if err != nil {
			return AppConfig{}, fmt.Errorf("invalid stats_interval: %w", err)
		}
		cfg.statsEvery = interval
	}
	if err := validateStatsInterval(cfg.statsEvery); err != nil {
		return AppConfig{}, fmt.Errorf("invalid stats_interval: %w", err)
	}

	return cfg, nil
}

func loadDomainRules(filter *XDPFilter, domains []string, flags uint32, label string) error {
	for _, item := range dedupeStrings(domains) {
		names := domainVariants(item)
		for _, name := range names {
			normalized, err := filter.AddDomainRule(name, flags)
			if err != nil {
				return err
			}
			log.WithFields(log.Fields{
				"domain": normalized,
				"rule":   label,
			}).Info("domain rule loaded")
		}
	}
	return nil
}

func validateStatsInterval(interval time.Duration) error {
	if interval <= 0 {
		return fmt.Errorf("must be positive")
	}
	return nil
}

func domainVariants(domain string) []string {
	normalized := normalizeDomain(domain)
	if normalized == "" {
		return nil
	}

	variants := []string{normalized}
	if !strings.HasPrefix(normalized, "www.") {
		variants = append(variants, "www."+normalized)
	}
	return variants
}

func loadCIDRRules(filter *XDPFilter, rules []string) error {
	for _, item := range dedupeStrings(rules) {
		prefix, err := parseIPPrefix(item)
		if err != nil {
			return err
		}

		loaded, err := filter.AddCIDR(prefix)
		if err != nil {
			return err
		}
		log.WithField("cidr", loaded).Info("IP/CIDR rule loaded")
	}
	return nil
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

func loadIPPortRules(filter *XDPFilter, rules []IPPortRuleConfig) error {
	seen := make(map[string]struct{}, len(rules))
	for _, rule := range rules {
		addr, port, proto, err := parseIPPortRule(rule)
		if err != nil {
			return err
		}

		key := fmt.Sprintf("%s/%d/%d", addr.String(), port, proto)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}

		loaded, err := filter.AddIPPort(addr, port, proto)
		if err != nil {
			return err
		}
		log.WithField("rule", loaded).Info("IP+port rule loaded")
	}
	return nil
}

func parseIPPortRule(rule IPPortRuleConfig) (netip.Addr, uint16, uint8, error) {
	addr, err := netip.ParseAddr(strings.TrimSpace(rule.IP))
	if err != nil {
		return netip.Addr{}, 0, 0, err
	}
	addr = addr.Unmap()
	if !addr.Is4() && !addr.Is6() {
		return netip.Addr{}, 0, 0, fmt.Errorf("%s is not an IP address", rule.IP)
	}
	if rule.Port == 0 {
		return netip.Addr{}, 0, 0, fmt.Errorf("invalid port 0 for %s", addr.String())
	}

	proto, err := parseProto(rule.Proto)
	if err != nil {
		return netip.Addr{}, 0, 0, err
	}

	return addr, rule.Port, proto, nil
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

func dedupeStrings(items []string) []string {
	out := make([]string, 0, len(items))
	seen := make(map[string]struct{}, len(items))

	for _, item := range items {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		if _, ok := seen[item]; ok {
			continue
		}
		seen[item] = struct{}{}
		out = append(out, item)
	}

	return out
}

func printStats(filter *XDPFilter) {
	stats, err := filter.GetStats()
	if err != nil {
		log.WithError(err).Warn("failed to read stats")
		return
	}

	log.WithFields(log.Fields{
		"total":           stats["total"],
		"passed":          stats["passed"],
		"http_blocked":    stats["http_blocked"],
		"tls_blocked":     stats["tls_blocked"],
		"dns_poisoned":    stats["dns_poisoned"],
		"ip_blocked":      stats["ip_blocked"],
		"ip_port_blocked": stats["ip_port_blocked"],
		"malformed":       stats["malformed"],
	}).Info("XDP stats")
}
