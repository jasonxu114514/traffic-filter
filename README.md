# Middle Filter

Middle Filter is a Linux x86_64 traffic filter. The default engine is now
NFQUEUE: nftables or iptables/ip6tables sends selected packets to Go, and Go
decides whether to accept, drop, or return a DNS NXDOMAIN response.

The old L7 XDP parser is no longer loaded by the default build. This avoids BPF
verifier instruction-limit failures when parsing HTTP, TLS, and DNS.

## Features

- HTTP Host blocking for IPv4 and IPv6 TCP/80.
- TLS SNI blocking for IPv4 and IPv6 TCP/443.
- DNS NXDOMAIN or drop mode for configured UDP/53 queries.
- IPv4, IPv6, and CIDR blocking.
- IPv4/IPv6 + port blocking for TCP and UDP.
- Automatic firewall rule management with nftables or iptables/ip6tables.
- Runtime counters for total, passed, HTTP/TLS/DNS/IP/IP+port hits, and malformed packets.

There are no built-in blocked domains. Every rule comes from `config.json`.

## Traffic Model

NFQUEUE sees packets selected by firewall hooks.

- Local inbound traffic is handled through `input`.
- Local outbound traffic is handled through `output`.
- Gateway or transit traffic is handled through `forward`.

By default, `chains` includes all three: `input`, `output`, and `forward`.

The program does not change `rp_filter`. Most deployments do not need to touch
it. Check `rp_filter` only for routing-level problems such as asymmetric
routing, policy routing, or unusual forwarding topologies.

## Engines

- `nfqueue`: implemented default engine. Go handles HTTP/TLS/DNS/IP decisions.
- `af_xdp`: config-recognized placeholder for a future userspace packet path.
- `xdp_fast_path`: scaffolded placeholder for future simple IP/CIDR/IP+port drops.

AF_XDP can be a good future fit for high performance, but it requires a full
userspace forwarding/reinjection path. It is not a simple replacement for
`XDP_PASS`, so this version prioritizes NFQUEUE for correctness and easier
deployment.

## Build

Requirements on the Linux server:

```bash
sudo apt-get update
sudo apt-get install -y golang-go make nftables iptables dnsutils curl
```

Build:

```bash
make clean
make build
```

`make build` builds the default NFQUEUE binary and does not require clang,
libbpf, or `bpf/filter.bpf.o`.

## Configuration

The CLI only accepts `-config`. If omitted, it reads `./config.json`.

```bash
sudo ./middle-filter -config config.json
```

Example:

```json
{
  "engine": "nfqueue",
  "debug": false,
  "stats_interval": "5s",
  "rules": {
    "domains": ["example.com"],
    "dns_poison_domains": ["example.com"],
    "ips": ["203.0.113.10", "198.51.100.0/24", "2001:db8::/32"],
    "ip_ports": [
      { "ip": "1.2.3.4", "port": 443, "proto": "tcp" },
      { "ip": "2001:db8::1", "port": 443, "proto": "tcp" }
    ]
  },
  "nfqueue": {
    "queue_num": 100,
    "firewall_backend": "auto",
    "install_rules": true,
    "chains": ["input", "output", "forward"],
    "capture": "l7",
    "fail_open": false,
    "dns_mode": "nxdomain"
  },
  "af_xdp": {
    "iface": "ens18",
    "mode": "disabled"
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

NFQUEUE options:

- `firewall_backend`: `auto`, `nftables`, `iptables`, `iptables-legacy`,
  `none`, or `disabled`.
  `auto` tries `nft` first when present, then falls back to
  `iptables`/`ip6tables` and `iptables-legacy`/`ip6tables-legacy` if nftables
  rule installation fails.
- `install_rules`: when true, rules are installed at startup and removed on a
  clean shutdown.
- `chains`: any of `input`, `output`, and `forward`.
- `capture`: `l7` queues TCP/80, TCP/443, and UDP/53. `all` queues all packets
  so Go can enforce IP/CIDR/IP+port rules for every protocol, with a higher
  performance cost.
- `fail_open`: enables NFQUEUE bypass behavior when supported by the firewall.
- `dns_mode`: `nxdomain` returns a crafted NXDOMAIN response; `drop` drops the
  DNS query.

## IPv6 Notes

IPv6 is supported for HTTP Host, TLS SNI, DNS NXDOMAIN/drop, CIDR, and IP+port
rules when packets are queued to NFQUEUE.

Current limits:

- TLS probing depends on cleartext ClientHello SNI. ECH hides SNI.
- QUIC/HTTP3 over UDP/443 is not parsed as TLS SNI.
- Fragmented traffic may not contain enough L4 payload in one queued packet for
  HTTP/TLS/DNS matching.
- With `capture: "l7"`, IP/CIDR and IP+port rules are evaluated only for
  queued TCP/80, TCP/443, and UDP/53 packets. Use `capture: "all"` for full
  packet coverage.

## Firewall Cleanup

On clean shutdown, auto-installed rules are removed. If the process crashes,
manual cleanup may be needed.

nftables:

```bash
sudo nft delete table inet middle_filter
```

List and remove matching NFQUEUE rules if needed:

```bash
sudo iptables -S | grep NFQUEUE
sudo ip6tables -S | grep NFQUEUE
sudo iptables-legacy -S | grep NFQUEUE
sudo ip6tables-legacy -S | grep NFQUEUE
```

## Remote Server Test Guide

Run these on the Linux server where traffic reaches the selected hooks.

1. Install dependencies and build:

```bash
sudo apt-get update
sudo apt-get install -y golang-go make nftables iptables dnsutils curl
make clean
make build
```

2. Create `config.json` from `config.example.json`, then start:

```bash
cp config.example.json config.json
sudo ./middle-filter -config config.json
```

3. HTTP domain tests:

```bash
curl -4 --connect-timeout 5 http://example.com
curl -6 --connect-timeout 5 http://example.com
```

Expected for configured domains: timeout, connection failure, or no response,
and `http_blocked` increases.

4. TLS SNI tests:

```bash
curl -4 --connect-timeout 5 https://example.com
curl -6 --connect-timeout 5 https://example.com
```

Expected for configured domains: timeout, TLS/connect failure, or no response,
and `tls_blocked` increases.

5. DNS poison tests:

```bash
dig @8.8.8.8 example.com A
dig @2001:4860:4860::8888 example.com AAAA
```

Expected for configured `dns_poison_domains`: NXDOMAIN and increasing
`dns_poisoned` counter.

6. IP/CIDR tests:

With default `capture: "l7"`, test IP/CIDR on TCP/80, TCP/443, or UDP/53. For
all packet types, switch to `capture: "all"` first.

```bash
curl -4 --connect-timeout 5 http://203.0.113.10
curl -6 --connect-timeout 5 http://[2001:db8::1]
ping -c 3 203.0.113.10
ping6 -c 3 2001:db8::1
```

Expected for configured IP/CIDR rules: timeout/drop and increasing
`ip_blocked` counter. `ping` requires `capture: "all"`.

7. IP+port tests:

```bash
curl -4 --connect-timeout 5 https://1.2.3.4
curl -6 --connect-timeout 5 https://[2001:db8::1]
dig @8.8.8.8 example.org A
```

Expected for configured IP+port rules: timeout/drop and increasing
`ip_port_blocked` counter.

8. Watch counters in the program logs:

- `http_blocked`
- `tls_blocked`
- `dns_poisoned`
- `dns_blocked`
- `ip_blocked`
- `ip_port_blocked`

## Files

- `config.example.json`: example JSON configuration.
- `main.go`: config loading, engine startup, signal handling, and stats loop.
- `nfqueue_engine_linux.go`: Linux NFQUEUE runtime.
- `packet_classifier.go`: Go packet parser and verdict logic.
- `firewall_linux.go`: nftables and iptables/ip6tables rule management.
- `xdp.go`: optional XDP loader behind the `xdp` build tag.
- `bpf/filter.bpf.c`: legacy/experimental BPF source, not used by default build.
