package config

import (
	"encoding/binary"
	"fmt"
	"net"
	"strconv"
	"strings"
)

// DNSMode defines how DNS queries are handled.
type DNSMode uint32

const (
	DNSModeDrop   DNSMode = 0
	DNSModePoison DNSMode = 1
)

// BlockMode bitmask for IP blocking.
type BlockMode uint32

const (
	BlockTCP  BlockMode = 1 << iota // 1
	BlockUDP                        // 2
	BlockICMP                       // 4
	BlockAll  BlockMode = BlockTCP | BlockUDP | BlockICMP
)

// Config holds all runtime configuration.
type Config struct {
	Interface string
	Domains   []string
	IPs       []uint32       // IPv4 addrs in network byte order
	IPPorts   []IPPortEntry  // IP:Port:Proto entries
	DNSMode   DNSMode
	IPMode    BlockMode // which protocols to block for IP rules
	IPPortMode BlockMode // which protocols to block for IP:Port rules (TCP/UDP only)
	Debug     bool
}

// IPPortEntry represents a single IP:Port rule.
type IPPortEntry struct {
	IP    uint32 // network byte order
	Port  uint16 // network byte order
	Proto uint8  // IPPROTO_TCP=6, IPPROTO_UDP=17
}

// Parse parses command-line flags and returns a validated Config.
func Parse(args []string) (*Config, error) {
	cfg := &Config{
		DNSMode:    DNSModeDrop,
		IPMode:     BlockAll,
		IPPortMode: BlockTCP | BlockUDP,
	}

	// Manual flag parsing for simplicity (avoids flag.FlagSet overhead)
	i := 0
	for i < len(args) {
		switch args[i] {
		case "-iface":
			i++
			if i >= len(args) {
				return nil, fmt.Errorf("-iface requires a value")
			}
			cfg.Interface = args[i]

		case "-domains":
			i++
			if i >= len(args) {
				return nil, fmt.Errorf("-domains requires a value")
			}
			cfg.Domains = splitAndTrim(args[i])

		case "-block-ips":
			i++
			if i >= len(args) {
				return nil, fmt.Errorf("-block-ips requires a value")
			}
			ips, err := parseIPList(args[i])
			if err != nil {
				return nil, fmt.Errorf("invalid -block-ips: %w", err)
			}
			cfg.IPs = ips

		case "-block-ip-ports":
			i++
			if i >= len(args) {
				return nil, fmt.Errorf("-block-ip-ports requires a value")
			}
			entries, err := parseIPPortList(args[i])
			if err != nil {
				return nil, fmt.Errorf("invalid -block-ip-ports: %w", err)
			}
			cfg.IPPorts = entries

		case "-dns-mode":
			i++
			if i >= len(args) {
				return nil, fmt.Errorf("-dns-mode requires a value")
			}
			switch strings.ToLower(args[i]) {
			case "drop":
				cfg.DNSMode = DNSModeDrop
			case "poison":
				cfg.DNSMode = DNSModePoison
			default:
				return nil, fmt.Errorf("invalid -dns-mode: %s (use drop or poison)", args[i])
			}

		case "-ip-mode":
			i++
			if i >= len(args) {
				return nil, fmt.Errorf("-ip-mode requires a value")
			}
			mode, err := parseBlockMode(args[i], true)
			if err != nil {
				return nil, fmt.Errorf("invalid -ip-mode: %w", err)
			}
			cfg.IPMode = mode

		case "-ip-port-mode":
			i++
			if i >= len(args) {
				return nil, fmt.Errorf("-ip-port-mode requires a value")
			}
			mode, err := parseBlockMode(args[i], false)
			if err != nil {
				return nil, fmt.Errorf("invalid -ip-port-mode: %w", err)
			}
			cfg.IPPortMode = mode

		case "-debug":
			cfg.Debug = true

		default:
			return nil, fmt.Errorf("unknown flag: %s", args[i])
		}
		i++
	}

	// Defaults
	if cfg.Interface == "" {
		cfg.Interface = "eth0"
	}
	if len(cfg.Domains) == 0 {
		cfg.Domains = []string{"pornhub.com", "www.pornhub.com"}
	}

	return cfg, nil
}

// ─── helpers ─────────────────────────────────────────────────────────────

func splitAndTrim(s string) []string {
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

// parseIPList parses "1.2.3.4,5.6.7.8" into network-order uint32s.
func parseIPList(s string) ([]uint32, error) {
	parts := splitAndTrim(s)
	out := make([]uint32, 0, len(parts))
	for _, p := range parts {
		ip := net.ParseIP(p)
		if ip == nil {
			return nil, fmt.Errorf("invalid IP: %s", p)
		}
		ip4 := ip.To4()
		if ip4 == nil {
			return nil, fmt.Errorf("only IPv4 supported: %s", p)
		}
		out = append(out, binary.BigEndian.Uint32(ip4))
	}
	return out, nil
}

// parseIPPortList parses "1.2.3.4:80:tcp,1.2.3.4:443:tcp" into IPPortEntry.
func parseIPPortList(s string) ([]IPPortEntry, error) {
	parts := splitAndTrim(s)
	out := make([]IPPortEntry, 0, len(parts))
	for _, p := range parts {
		fields := strings.Split(p, ":")
		if len(fields) < 2 || len(fields) > 3 {
			return nil, fmt.Errorf("expected IP:Port[:proto], got: %s", p)
		}

		ip := net.ParseIP(fields[0])
		if ip == nil {
			return nil, fmt.Errorf("invalid IP: %s", fields[0])
		}
		ip4 := ip.To4()
		if ip4 == nil {
			return nil, fmt.Errorf("only IPv4 supported: %s", fields[0])
		}

		port, err := strconv.ParseUint(fields[1], 10, 16)
		if err != nil {
			return nil, fmt.Errorf("invalid port: %s", fields[1])
		}

		proto := "tcp"
		if len(fields) == 3 {
			proto = strings.ToLower(fields[2])
		}

		var protoNum uint8
		switch proto {
		case "tcp":
			protoNum = 6 // IPPROTO_TCP
		case "udp":
			protoNum = 17 // IPPROTO_UDP
		default:
			return nil, fmt.Errorf("unsupported protocol: %s (use tcp or udp)", proto)
		}

		out = append(out, IPPortEntry{
			IP:    binary.BigEndian.Uint32(ip4),
			Port:  uint16(port),
			Proto: protoNum,
		})
	}
	return out, nil
}

// parseBlockMode parses "tcp,udp,icmp" or "tcp,udp" into a bitmask.
func parseBlockMode(s string, allowICMP bool) (BlockMode, error) {
	parts := splitAndTrim(s)
	if len(parts) == 0 {
		return 0, fmt.Errorf("empty mode string")
	}

	var mode BlockMode
	for _, p := range parts {
		switch strings.ToLower(p) {
		case "tcp":
			mode |= BlockTCP
		case "udp":
			mode |= BlockUDP
		case "icmp":
			if !allowICMP {
				return 0, fmt.Errorf("ICMP not allowed for IP:Port mode")
			}
			mode |= BlockICMP
		case "all":
			if allowICMP {
				return BlockAll, nil
			}
			return BlockTCP | BlockUDP, nil
		default:
			return 0, fmt.Errorf("unknown protocol: %s", p)
		}
	}
	return mode, nil
}
