package main

import (
	"fmt"
	"net"
	"strconv"
	"strings"
)

type config struct {
	Iface   string
	Domains []string
	IPs     []net.IP
	IPPorts []ipPortRule
	DNSMode string // "drop" or "poison"
	Debug   bool
}

type ipPortRule struct {
	IP    net.IP
	Port  uint16
	Proto string // "tcp" or "udp"
}

func parseArgs(args []string) (*config, error) {
	c := &config{DNSMode: "drop"}
	i := 0
	for i < len(args) {
		switch args[i] {
		case "-iface":
			i++; c.Iface = val(args, i)
		case "-domains":
			i++; c.Domains = splitTrim(val(args, i))
		case "-block-ips":
			i++
			for _, s := range splitTrim(val(args, i)) {
				ip := net.ParseIP(s)
				if ip == nil || ip.To4() == nil {
					return nil, fmt.Errorf("invalid IP: %s", s)
				}
				c.IPs = append(c.IPs, ip.To4())
			}
		case "-block-ip-ports":
			i++
			for _, s := range splitTrim(val(args, i)) {
				r, err := parseIPPort(s)
				if err != nil {
					return nil, err
				}
				c.IPPorts = append(c.IPPorts, r)
			}
		case "-dns-mode":
			i++; v := val(args, i)
			if v != "drop" && v != "poison" {
				return nil, fmt.Errorf("invalid dns-mode: %s", v)
			}
			c.DNSMode = v
		case "-debug":
			c.Debug = true
		default:
			return nil, fmt.Errorf("unknown flag: %s", args[i])
		}
		i++
	}
	if c.Iface == "" {
		c.Iface = "eth0"
	}
	if len(c.Domains) == 0 {
		c.Domains = []string{"pornhub.com", "www.pornhub.com"}
	}
	return c, nil
}

func parseIPPort(s string) (ipPortRule, error) {
	p := strings.Split(s, ":")
	if len(p) < 2 || len(p) > 3 {
		return ipPortRule{}, fmt.Errorf("format IP:Port[:proto]: %s", s)
	}
	ip := net.ParseIP(p[0])
	if ip == nil || ip.To4() == nil {
		return ipPortRule{}, fmt.Errorf("invalid IP: %s", p[0])
	}
	port, err := strconv.ParseUint(p[1], 10, 16)
	if err != nil {
		return ipPortRule{}, fmt.Errorf("invalid port: %s", p[1])
	}
	proto := "tcp"
	if len(p) == 3 {
		proto = strings.ToLower(p[2])
		if proto != "tcp" && proto != "udp" {
			return ipPortRule{}, fmt.Errorf("proto must be tcp or udp: %s", proto)
		}
	}
	return ipPortRule{IP: ip.To4(), Port: uint16(port), Proto: proto}, nil
}

func val(args []string, i int) string {
	if i >= len(args) {
		return ""
	}
	return args[i]
}

func splitTrim(s string) []string {
	var out []string
	for _, x := range strings.Split(s, ",") {
		x = strings.TrimSpace(x)
		if x != "" {
			out = append(out, x)
		}
	}
	return out
}
