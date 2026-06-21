package main

import (
	"fmt"
	"net/netip"
	"strings"
)

const (
	protoTCP uint8 = 6
	protoUDP uint8 = 17
)

type RuleSet struct {
	Domains          map[string]struct{}
	DNSPoisonDomains map[string]struct{}
	Prefixes         []netip.Prefix
	IPPorts          map[ipPortRule]struct{}
}

type ipPortRule struct {
	Addr  netip.Addr
	Port  uint16
	Proto uint8
}

func compileRuleSet(cfg RuleConfig) (RuleSet, error) {
	rules := RuleSet{
		Domains:          make(map[string]struct{}),
		DNSPoisonDomains: make(map[string]struct{}),
		IPPorts:          make(map[ipPortRule]struct{}),
	}

	for _, domain := range dedupeStrings(cfg.Domains) {
		for _, variant := range domainVariants(domain) {
			rules.Domains[variant] = struct{}{}
		}
	}

	for _, domain := range dedupeStrings(cfg.DNSPoisonDomains) {
		for _, variant := range domainVariants(domain) {
			rules.DNSPoisonDomains[variant] = struct{}{}
		}
	}

	for _, raw := range dedupeStrings(cfg.IPs) {
		prefix, err := parseIPPrefix(raw)
		if err != nil {
			return RuleSet{}, err
		}
		rules.Prefixes = append(rules.Prefixes, prefix)
	}

	for _, rule := range cfg.IPPorts {
		parsed, err := parseIPPortRule(rule)
		if err != nil {
			return RuleSet{}, err
		}
		rules.IPPorts[parsed] = struct{}{}
	}

	return rules, nil
}

func parseIPPortRule(rule IPPortRuleConfig) (ipPortRule, error) {
	addr, err := netip.ParseAddr(strings.TrimSpace(rule.IP))
	if err != nil {
		return ipPortRule{}, err
	}
	addr = addr.Unmap()
	if !addr.Is4() && !addr.Is6() {
		return ipPortRule{}, fmt.Errorf("%s is not an IP address", rule.IP)
	}
	if rule.Port == 0 {
		return ipPortRule{}, fmt.Errorf("invalid port 0 for %s", addr.String())
	}

	proto, err := parseProto(rule.Proto)
	if err != nil {
		return ipPortRule{}, err
	}

	return ipPortRule{Addr: addr, Port: rule.Port, Proto: proto}, nil
}

func (r RuleSet) matchDomain(domain string) bool {
	_, ok := r.Domains[normalizeDomain(domain)]
	return ok
}

func (r RuleSet) matchDNSPoison(domain string) bool {
	_, ok := r.DNSPoisonDomains[normalizeDomain(domain)]
	return ok
}

func (r RuleSet) matchIP(addr netip.Addr) bool {
	addr = addr.Unmap()
	for _, prefix := range r.Prefixes {
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
}

func (r RuleSet) matchIPPort(addr netip.Addr, port uint16, proto uint8) bool {
	addr = addr.Unmap()
	_, ok := r.IPPorts[ipPortRule{Addr: addr, Port: port, Proto: proto}]
	return ok
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
