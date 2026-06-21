# Middle Filter

Middle Filter is a Linux x86_64 XDP/eBPF ingress filter. It attaches to one
interface and inspects IPv4 and IPv6 packets before they enter the kernel
network stack.

It does not use tun devices, iptables, nftables, or NFQUEUE.

## Features

- HTTP Host blocking for IPv4 and IPv6 TCP/80.
- TLS SNI blocking for IPv4 and IPv6 TCP/443.
- DNS NXDOMAIN poisoning for configured IPv4 and IPv6 UDP/53 queries.
- IPv4, IPv6, and CIDR blocking.
- IPv4/IPv6 + port blocking for TCP and UDP.
- Runtime counters for total, passed, HTTP/TLS/DNS/IP/IP+port hits, and malformed packets.

There are no built-in blocked domains. Every domain rule comes from
`config.json`.

## Traffic Model

XDP is an ingress hook. Attach the program to the interface that receives the
traffic you want to inspect.

- Gateway or transit use works when packets enter the attached interface.
- Local inbound traffic can be handled on the receiving interface.
- Local outbound traffic from the same host usually is not seen by XDP on a
  normal NIC send path. Put the filter at a gateway, bridge ingress point,
  container host veth ingress, or another middle point where packets arrive.

The program does not change `rp_filter`. Most deployments do not need to touch
it. Check `rp_filter` only for routing-level problems such as asymmetric
routing, policy routing, or unusual forwarding topologies.

## XDP Modes

- `generic`: Kernel generic XDP. Best compatibility, lower performance.
- `driver` or `native`: Native driver XDP. Better performance, requires NIC
  driver support.
- `auto`: Do not force generic or driver flags; let the kernel/library attach
  with default behavior.

Start with `generic` for compatibility, then try `driver` on supported NICs.

## Build

Requirements on the Linux server:

```bash
sudo apt-get update
sudo apt-get install -y clang llvm libbpf-dev golang-go make
```

Build:

```bash
make clean
make build
```

`make build` compiles `bpf/filter.bpf.c` to `bpf/filter.bpf.o`, then embeds the
BPF object into the Go binary.

## Configuration

The CLI only accepts `-config`. If omitted, it reads `./config.json`.

```bash
sudo ./middle-filter -config config.json
```

Example:

```json
{
  "iface": "ens18",
  "xdp_mode": "generic",
  "debug": false,
  "stats_interval": "5s",
  "rules": {
    "domains": ["example.com"],
    "dns_poison_domains": ["example.com"],
    "ips": ["203.0.113.10", "198.51.100.0/24", "2001:db8::/32"],
    "ip_ports": [
      { "ip": "1.2.3.4", "port": 443, "proto": "tcp" },
      { "ip": "8.8.8.8", "port": 53, "proto": "udp" },
      { "ip": "2001:db8::1", "port": 443, "proto": "tcp" }
    ]
  }
}
```

Rules:

- `domains`: exact HTTP Host and TLS SNI rules. The loader also adds one
  `www.` variant for names that do not already start with `www.`.
- `dns_poison_domains`: exact DNS query names to answer with NXDOMAIN. The
  loader also adds one `www.` variant.
- `ips`: IPv4/IPv6 addresses or CIDRs. Bare IPs become `/32` for IPv4 and
  `/128` for IPv6.
- `ip_ports`: structured IP, port, and protocol rules. `proto` may be `tcp` or
  `udp`; empty `proto` defaults to `tcp`.
- Domain rules are limited to 63 bytes after normalization.

## IPv6 Notes

IPv6 TCP/UDP fixed-header packets are supported for domain, DNS poison,
CIDR, and IP+port rules.

Current limits:

- IPv6 extension headers are passed through.
- Fragmented IPv4 packets are passed through.
- TLS probing depends on cleartext ClientHello SNI. ECH hides SNI.
- QUIC/HTTP3 over UDP/443 is not parsed.
- HTTP/TLS/DNS parsing reads within the first 1024 bytes of the packet.

## Remote Server Test Guide

Run these on the Linux server where traffic reaches the selected interface.

1. Install dependencies and build:

```bash
sudo apt-get update
sudo apt-get install -y clang llvm libbpf-dev golang-go make dnsutils curl
make clean
make build
```

2. Find the interface:

```bash
ip link
ip route
ip -6 route
```

3. Create `config.json` from `config.example.json`, set `iface`, and start:

```bash
sudo ./middle-filter -config config.json
```

4. HTTP domain tests:

```bash
curl -4 --connect-timeout 5 http://example.com
curl -6 --connect-timeout 5 http://example.com
```

Expected for configured domains: timeout, connection failure, or no response.

5. TLS SNI tests:

```bash
curl -4 --connect-timeout 5 https://example.com
curl -6 --connect-timeout 5 https://example.com
```

Expected for configured domains: timeout, TLS/connect failure, or no response.

6. DNS poison tests:

```bash
dig @8.8.8.8 example.com A
dig @2001:4860:4860::8888 example.com AAAA
```

Expected for configured `dns_poison_domains`: NXDOMAIN and increasing
`dns_poisoned` counter.

7. IP/CIDR tests:

```bash
ping -c 3 203.0.113.10
ping6 -c 3 2001:db8::1
curl -4 --connect-timeout 5 http://203.0.113.10
curl -6 --connect-timeout 5 http://[2001:db8::1]
```

Expected for configured IP/CIDR rules: timeout/drop and increasing
`ip_blocked` counter.

8. IP+port tests:

```bash
curl -4 --connect-timeout 5 https://1.2.3.4
curl -6 --connect-timeout 5 https://[2001:db8::1]
dig @8.8.8.8 example.org A
```

Expected for configured IP+port rules: timeout/drop and increasing
`ip_port_blocked` counter.

9. Watch counters in the program logs:

- `http_blocked`
- `tls_blocked`
- `dns_poisoned`
- `ip_blocked`
- `ip_port_blocked`

## Files

- `config.example.json`: example JSON configuration.
- `bpf/filter.bpf.c`: XDP/eBPF packet parsing and blocking logic.
- `bpf/vmlinux.h`: minimal Linux x86_64 type definitions.
- `xdp.go`: BPF loader, map ABI, rule updates, and stats reads.
- `main.go`: config loading and run loop.
- `Makefile`: Linux x86_64 build entrypoint.
