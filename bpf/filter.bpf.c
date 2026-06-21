// filter.bpf.c - XDP middle filter for HTTP/TLS/DNS/IP rules.
//
// Scope: Linux x86_64, IPv4/IPv6 fixed headers, ingress XDP.
// No tun, iptables, nftables, or NFQUEUE.

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

char LICENSE[] SEC("license") = "GPL";

#ifndef __noinline
#define __noinline __attribute__((noinline))
#endif

#define NO_UNROLL _Pragma("clang loop unroll(disable)")

#define MAX_DOMAIN_LEN 96
#define MAX_HTTP_SCAN 256
#define MAX_TLS_SCAN 512
#define MAX_DNS_SCAN 128
#define MAX_DNS_LABELS 16
#define MAX_PACKET_READ 1024

#define DOMAIN_HTTP 1
#define DOMAIN_TLS 2
#define DOMAIN_DNS_POISON 4

#define DISPATCH_IPV4 0
#define DISPATCH_IPV6 1
#define DISPATCH_TCP4 2
#define DISPATCH_UDP4 3
#define DISPATCH_TCP6 4
#define DISPATCH_UDP6 5
#define DISPATCH_HTTP4 6
#define DISPATCH_TLS4 7
#define DISPATCH_HTTP6 8
#define DISPATCH_TLS6 9
#define DISPATCH_DNS4 10
#define DISPATCH_DNS6 11

#define STAT_TOTAL 0
#define STAT_PASSED 1
#define STAT_HTTP_BLOCKED 2
#define STAT_TLS_BLOCKED 3
#define STAT_DNS_POISONED 4
#define STAT_IP_BLOCKED 5
#define STAT_IP_PORT_BLOCKED 6
#define STAT_MALFORMED 7
#define STAT_MAX 8

struct domain_key {
    char name[MAX_DOMAIN_LEN];
};

struct lpm_v4_key {
    __u32 prefixlen;
    __u32 addr;
};

struct lpm_v6_key {
    __u32 prefixlen;
    __u8 addr[16];
};

struct ip_port_key {
    __u32 addr;
    __u16 port;
    __u8 proto;
    __u8 pad;
};

struct ip_port_v6_key {
    __u8 addr[16];
    __u16 port;
    __u8 proto;
    __u8 pad;
};

struct dnshdr {
    __u16 id;
    __u16 flags;
    __u16 qdcount;
    __u16 ancount;
    __u16 nscount;
    __u16 arcount;
} __attribute__((packed));

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 2048);
    __type(key, struct domain_key);
    __type(value, __u32);
} domain_rules SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, 4096);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, struct lpm_v4_key);
    __type(value, __u32);
} cidr_rules SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, 4096);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, struct lpm_v6_key);
    __type(value, __u32);
} cidr_v6_rules SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, struct ip_port_key);
    __type(value, __u32);
} ip_port_rules SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, struct ip_port_v6_key);
    __type(value, __u32);
} ip_port_v6_rules SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, STAT_MAX);
    __type(key, __u32);
    __type(value, __u64);
} stats SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(max_entries, 12);
    __type(key, __u32);
    __type(value, __u32);
} dispatch_rules SEC(".maps");

static __always_inline void inc_stat(__u32 key)
{
    __u64 *val = bpf_map_lookup_elem(&stats, &key);
    if (val)
        __sync_fetch_and_add(val, 1);
}

static __always_inline __u8 ascii_lower(__u8 c)
{
    if (c >= 'A' && c <= 'Z')
        return c + 32;
    return c;
}

static __always_inline int load_u8(void *data, void *data_end, __u32 off, __u8 *out)
{
    if (off >= MAX_PACKET_READ)
        return 0;

    char *p = data;
    if (p + off + 1 > (char *)data_end)
        return 0;

    *out = *(__u8 *)(p + off);
    return 1;
}

static __always_inline int load_be16(void *data, void *data_end, __u32 off, __u16 *out)
{
    __u8 hi = 0, lo = 0;

    if (!load_u8(data, data_end, off, &hi))
        return 0;
    if (!load_u8(data, data_end, off + 1, &lo))
        return 0;

    *out = ((__u16)hi << 8) | lo;
    return 1;
}

static __always_inline void swap_macs(struct ethhdr *eth)
{
    __u8 tmp = 0;

    NO_UNROLL
    for (int i = 0; i < 6; i++) {
        tmp = eth->h_source[i];
        eth->h_source[i] = eth->h_dest[i];
        eth->h_dest[i] = tmp;
    }
}

static __always_inline __u16 csum_replace16(__u16 check, __u16 old, __u16 new)
{
    __u32 sum = (~bpf_ntohs(check)) & 0xffff;

    sum += (~bpf_ntohs(old)) & 0xffff;
    sum += bpf_ntohs(new);
    sum = (sum & 0xffff) + (sum >> 16);
    sum = (sum & 0xffff) + (sum >> 16);

    __u16 out = (__u16)~sum;
    if (out == 0)
        out = 0xffff;
    return bpf_htons(out);
}

static __noinline int domain_matches(struct domain_key *key, __u32 len, __u32 action)
{
    if (len == 0 || len >= MAX_DOMAIN_LEN)
        return 0;

    __u32 *rule = bpf_map_lookup_elem(&domain_rules, key);
    if (!rule)
        return 0;

    return ((*rule & action) != 0);
}

static __noinline int domain_from_packet_matches(void *data, void *data_end,
                                                 __u32 off, __u32 len,
                                                 __u32 action)
{
    if (len == 0 || len >= MAX_DOMAIN_LEN)
        return 0;
    if (off >= MAX_PACKET_READ || len > MAX_PACKET_READ - off)
        return 0;

    struct domain_key key = {};

    NO_UNROLL
    for (int i = 0; i < MAX_DOMAIN_LEN; i++) {
        if ((__u32)i >= len)
            break;

        __u8 c = 0;
        if (!load_u8(data, data_end, off + i, &c))
            return 0;

        key.name[i] = ascii_lower(c);
    }

    return domain_matches(&key, len, action);
}

static __noinline int ip_matches_cidr(__u32 addr)
{
    struct lpm_v4_key key = {
        .prefixlen = 32,
        .addr = addr,
    };

    __u32 *rule = bpf_map_lookup_elem(&cidr_rules, &key);
    return rule != 0;
}

static __noinline int ip6_matches_cidr(__u8 addr[16])
{
    struct lpm_v6_key key = {
        .prefixlen = 128,
    };

    NO_UNROLL
    for (int i = 0; i < 16; i++)
        key.addr[i] = addr[i];

    __u32 *rule = bpf_map_lookup_elem(&cidr_v6_rules, &key);
    return rule != 0;
}

static __noinline int ip_port_matches(__u32 addr, __u16 port, __u8 proto)
{
    struct ip_port_key key = {
        .addr = addr,
        .port = port,
        .proto = proto,
        .pad = 0,
    };

    __u32 *rule = bpf_map_lookup_elem(&ip_port_rules, &key);
    return rule != 0;
}

static __noinline int ip6_port_matches(__u8 addr[16], __u16 port, __u8 proto)
{
    struct ip_port_v6_key key = {
        .port = port,
        .proto = proto,
        .pad = 0,
    };

    NO_UNROLL
    for (int i = 0; i < 16; i++)
        key.addr[i] = addr[i];

    __u32 *rule = bpf_map_lookup_elem(&ip_port_v6_rules, &key);
    return rule != 0;
}

static __noinline int check_http_host(void *data, void *data_end, __u32 payload_off)
{
    if (payload_off >= MAX_PACKET_READ)
        return XDP_PASS;

    __u32 scan_len = MAX_HTTP_SCAN;
    if (scan_len > MAX_PACKET_READ - payload_off)
        scan_len = MAX_PACKET_READ - payload_off;

    NO_UNROLL
    for (int i = 0; i < MAX_HTTP_SCAN; i++) {
        if ((__u32)i >= scan_len)
            break;

        __u32 off = payload_off + i;
        __u8 h = 0, o = 0, s = 0, t = 0, colon = 0;

        if (!load_u8(data, data_end, off, &h))
            break;
        if (!load_u8(data, data_end, off + 1, &o))
            break;
        if (!load_u8(data, data_end, off + 2, &s))
            break;
        if (!load_u8(data, data_end, off + 3, &t))
            break;
        if (!load_u8(data, data_end, off + 4, &colon))
            break;

        if (ascii_lower(h) != 'h' || ascii_lower(o) != 'o' ||
            ascii_lower(s) != 's' || ascii_lower(t) != 't' || colon != ':')
            continue;

        __u32 host_off = off + 5;
        if (host_off >= MAX_PACKET_READ)
            return XDP_PASS;

        NO_UNROLL
        for (int skip = 0; skip < 4; skip++) {
            __u8 c = 0;
            if (!load_u8(data, data_end, host_off, &c))
                return XDP_PASS;
            if (c != ' ' && c != '\t')
                break;
            host_off++;
            if (host_off >= MAX_PACKET_READ)
                return XDP_PASS;
        }

        __u32 host_len = 0;

        NO_UNROLL
        for (int j = 0; j < MAX_DOMAIN_LEN - 1; j++) {
            __u8 c = 0;
            if (!load_u8(data, data_end, host_off + j, &c))
                break;
            if (c == '\r' || c == '\n' || c == ' ' || c == '\t' || c == ':')
                break;
            host_len++;
        }

        if (domain_from_packet_matches(data, data_end, host_off, host_len, DOMAIN_HTTP))
            return XDP_DROP;

        return XDP_PASS;
    }

    return XDP_PASS;
}

static __noinline int check_tls_sni(void *data, void *data_end, __u32 payload_off)
{
    __u8 content_type = 0, version_major = 0, handshake_type = 0;

    if (payload_off >= MAX_PACKET_READ || payload_off > MAX_PACKET_READ - 6)
        return XDP_PASS;

    if (!load_u8(data, data_end, payload_off, &content_type))
        return XDP_PASS;
    if (!load_u8(data, data_end, payload_off + 1, &version_major))
        return XDP_PASS;
    if (!load_u8(data, data_end, payload_off + 5, &handshake_type))
        return XDP_PASS;

    if (content_type != 0x16 || version_major != 0x03 || handshake_type != 0x01)
        return XDP_PASS;

    __u32 tls_limit = payload_off + MAX_TLS_SCAN;
    if (tls_limit > MAX_PACKET_READ)
        tls_limit = MAX_PACKET_READ;

    if (payload_off > MAX_PACKET_READ - 44)
        return XDP_PASS;

    __u32 pos = payload_off + 43;
    __u8 session_len = 0;
    if (!load_u8(data, data_end, pos, &session_len))
        return XDP_PASS;

    __u32 next_pos = pos + 1 + session_len;
    if (next_pos < pos || next_pos > tls_limit)
        return XDP_PASS;
    pos = next_pos;
    if (pos + 2 < pos || pos + 2 > tls_limit)
        return XDP_PASS;

    __u16 cipher_len = 0;
    if (!load_be16(data, data_end, pos, &cipher_len))
        return XDP_PASS;
    if (cipher_len > MAX_TLS_SCAN)
        return XDP_PASS;

    next_pos = pos + 2 + cipher_len;
    if (next_pos < pos || next_pos > tls_limit)
        return XDP_PASS;
    pos = next_pos;
    if (pos + 1 < pos || pos + 1 > tls_limit)
        return XDP_PASS;

    __u8 compression_len = 0;
    if (!load_u8(data, data_end, pos, &compression_len))
        return XDP_PASS;
    if (compression_len > 32)
        return XDP_PASS;

    next_pos = pos + 1 + compression_len;
    if (next_pos < pos || next_pos > tls_limit)
        return XDP_PASS;
    pos = next_pos;
    if (pos + 2 < pos || pos + 2 > tls_limit)
        return XDP_PASS;

    __u16 extensions_len = 0;
    if (!load_be16(data, data_end, pos, &extensions_len))
        return XDP_PASS;

    next_pos = pos + 2;
    if (next_pos < pos || next_pos > tls_limit)
        return XDP_PASS;
    pos = next_pos;

    __u32 extensions_end = pos + extensions_len;
    if (extensions_end < pos || extensions_end > tls_limit)
        extensions_end = tls_limit;

    NO_UNROLL
    for (int i = 0; i < 16; i++) {
        if (pos > extensions_end || extensions_end - pos < 4)
            break;

        __u16 ext_type = 0, ext_len = 0;
        if (!load_be16(data, data_end, pos, &ext_type))
            break;
        if (!load_be16(data, data_end, pos + 2, &ext_len))
            break;

        next_pos = pos + 4;
        if (next_pos < pos || next_pos > tls_limit)
            break;
        pos = next_pos;

        if (pos > tls_limit || ext_len > MAX_TLS_SCAN || ext_len > tls_limit - pos)
            break;
        __u32 ext_end = pos + ext_len;

        if (ext_type == 0) {
            __u16 list_len = 0, name_len = 0;
            __u8 name_type = 0;

            if (ext_len < 5)
                return XDP_PASS;
            if (!load_be16(data, data_end, pos, &list_len))
                return XDP_PASS;
            if (!load_u8(data, data_end, pos + 2, &name_type))
                return XDP_PASS;
            if (!load_be16(data, data_end, pos + 3, &name_len))
                return XDP_PASS;

            if (name_type != 0 || list_len < 3 || name_len == 0 || name_len >= MAX_DOMAIN_LEN)
                return XDP_PASS;
            if (ext_len < 5 || name_len > ext_len - 5)
                return XDP_PASS;

            __u32 name_off = pos + 5;
            if (name_off < pos || name_off > tls_limit || name_len > tls_limit - name_off)
                return XDP_PASS;

            if (domain_from_packet_matches(data, data_end, name_off, name_len, DOMAIN_TLS))
                return XDP_DROP;

            return XDP_PASS;
        }

        pos = ext_end;
    }

    return XDP_PASS;
}

static __noinline int dns_domain_matches(void *data, void *data_end,
                                         __u32 dns_off, __u32 dns_payload_len)
{
    if (dns_off >= MAX_PACKET_READ || dns_off > MAX_PACKET_READ - sizeof(struct dnshdr))
        return 0;

    __u32 dns_end = dns_off + dns_payload_len;
    if (dns_end < dns_off || dns_end > MAX_PACKET_READ)
        return 0;

    char *packet = data;
    if (packet + dns_end > (char *)data_end)
        return 0;

    struct dnshdr *dns = (void *)(packet + dns_off);
    if ((void *)(dns + 1) > data_end)
        return 0;

    if (bpf_ntohs(dns->flags) & 0x8000)
        return 0;
    if (bpf_ntohs(dns->qdcount) == 0)
        return 0;

    struct domain_key key = {};
    __u32 pos = dns_off + sizeof(struct dnshdr);
    __u32 out = 0;
    __u8 label_remaining = 0;
    __u8 labels = 0;
    int complete = 0;

    NO_UNROLL
    for (int i = 0; i < MAX_DNS_SCAN; i++) {
        if (label_remaining == 0) {
            __u8 label_len = 0;
            if (pos >= dns_end)
                return 0;
            if (!load_u8(data, data_end, pos, &label_len))
                return 0;

            if (label_len == 0) {
                pos++;
                complete = 1;
                break;
            }
            if ((label_len & 0xc0) != 0 || label_len > 63)
                return 0;

            labels++;
            if (labels > MAX_DNS_LABELS)
                return 0;

            pos++;
            label_remaining = label_len;

            if (out > 0) {
                if (out >= MAX_DOMAIN_LEN - 1)
                    return 0;
                key.name[out++] = '.';
            }
            continue;
        }

        if (out >= MAX_DOMAIN_LEN - 1)
            return 0;
        if (pos >= dns_end)
            return 0;

        __u8 c = 0;
        if (!load_u8(data, data_end, pos, &c))
            return 0;

        key.name[out++] = ascii_lower(c);
        pos++;
        label_remaining--;
    }

    if (!complete)
        return 0;
    if (pos > dns_end || dns_end - pos < 4)
        return 0;

    return domain_matches(&key, out, DOMAIN_DNS_POISON);
}

static __always_inline int poison_dns_nxdomain_v4(struct ethhdr *eth, struct iphdr *ip,
                                                  struct udphdr *udp, struct dnshdr *dns)
{
    swap_macs(eth);

    __u32 ip_tmp = ip->saddr;
    ip->saddr = ip->daddr;
    ip->daddr = ip_tmp;

    __u16 port_tmp = udp->source;
    udp->source = udp->dest;
    udp->dest = port_tmp;

    dns->flags = bpf_htons(0x8183);
    dns->ancount = 0;
    dns->nscount = 0;
    dns->arcount = 0;

    // Swapping IPv4 source/destination leaves the header checksum unchanged.
    // UDP checksum 0 is valid for IPv4 and avoids rebuilding a pseudo-header.
    udp->check = 0;

    inc_stat(STAT_DNS_POISONED);
    return XDP_TX;
}

static __always_inline int poison_dns_nxdomain_v6(struct ethhdr *eth,
                                                  struct ipv6hdr *ip6,
                                                  struct udphdr *udp,
                                                  struct dnshdr *dns)
{
    swap_macs(eth);

    __u8 tmp = 0;
    NO_UNROLL
    for (int i = 0; i < 16; i++) {
        tmp = ip6->saddr[i];
        ip6->saddr[i] = ip6->daddr[i];
        ip6->daddr[i] = tmp;
    }

    __u16 port_tmp = udp->source;
    udp->source = udp->dest;
    udp->dest = port_tmp;

    __u16 old_flags = dns->flags;
    __u16 old_ancount = dns->ancount;
    __u16 old_nscount = dns->nscount;
    __u16 old_arcount = dns->arcount;

    dns->flags = bpf_htons(0x8183);
    dns->ancount = 0;
    dns->nscount = 0;
    dns->arcount = 0;

    udp->check = csum_replace16(udp->check, old_flags, dns->flags);
    udp->check = csum_replace16(udp->check, old_ancount, dns->ancount);
    udp->check = csum_replace16(udp->check, old_nscount, dns->nscount);
    udp->check = csum_replace16(udp->check, old_arcount, dns->arcount);

    inc_stat(STAT_DNS_POISONED);
    return XDP_TX;
}

static __always_inline int check_dns_v4(void *data, void *data_end, struct ethhdr *eth,
                                        struct iphdr *ip, struct udphdr *udp, __u32 dns_off)
{
    __u16 udp_len = bpf_ntohs(udp->len);
    if (udp_len < sizeof(struct udphdr) + sizeof(struct dnshdr))
        return XDP_PASS;

    __u32 dns_payload_len = (__u32)udp_len - sizeof(struct udphdr);
    if (!dns_domain_matches(data, data_end, dns_off, dns_payload_len))
        return XDP_PASS;

    char *packet = data;
    struct dnshdr *dns = (void *)(packet + dns_off);
    if ((void *)(dns + 1) > data_end)
        return XDP_PASS;

    if (ip->ihl != 5)
        return XDP_DROP;
    return poison_dns_nxdomain_v4(eth, ip, udp, dns);
}

static __always_inline int check_dns_v6(void *data, void *data_end, struct ethhdr *eth,
                                        struct ipv6hdr *ip6, struct udphdr *udp,
                                        __u32 udp_off, __u32 dns_off)
{
    __u16 udp_len = bpf_ntohs(udp->len);
    if (udp_len < sizeof(struct udphdr) + sizeof(struct dnshdr))
        return XDP_PASS;
    if (udp_off >= MAX_PACKET_READ || udp_len > MAX_PACKET_READ - udp_off)
        return XDP_PASS;

    __u32 dns_payload_len = (__u32)udp_len - sizeof(struct udphdr);
    if (!dns_domain_matches(data, data_end, dns_off, dns_payload_len))
        return XDP_PASS;

    char *packet = data;
    struct dnshdr *dns = (void *)(packet + dns_off);
    if ((void *)(dns + 1) > data_end)
        return XDP_PASS;

    return poison_dns_nxdomain_v6(eth, ip6, udp, dns);
}

static __always_inline int parse_tcp_ports(void *data, void *data_end, __u32 l4_off,
                                           __u32 *payload_off, __u16 *sport,
                                           __u16 *dport)
{
    struct tcphdr *tcp = (void *)((char *)data + l4_off);
    if ((void *)(tcp + 1) > data_end) {
        inc_stat(STAT_MALFORMED);
        return XDP_PASS;
    }

    __u8 tcp_doff = tcp->doff;
    if (tcp_doff < 5 || tcp_doff > 15) {
        inc_stat(STAT_MALFORMED);
        return XDP_PASS;
    }

    __u32 tcp_header_len = (__u32)tcp_doff * 4;
    if ((void *)tcp + tcp_header_len > data_end) {
        inc_stat(STAT_MALFORMED);
        return XDP_PASS;
    }

    *sport = bpf_ntohs(tcp->source);
    *dport = bpf_ntohs(tcp->dest);
    *payload_off = l4_off + tcp_header_len;
    return -1;
}

static __always_inline int run_http_rule(void *data, void *data_end, __u32 payload_off)
{
    int action = check_http_host(data, data_end, payload_off);
    if (action == XDP_DROP) {
        inc_stat(STAT_HTTP_BLOCKED);
        return XDP_DROP;
    }

    inc_stat(STAT_PASSED);
    return XDP_PASS;
}

static __always_inline int run_tls_rule(void *data, void *data_end, __u32 payload_off)
{
    int action = check_tls_sni(data, data_end, payload_off);
    if (action == XDP_DROP) {
        inc_stat(STAT_TLS_BLOCKED);
        return XDP_DROP;
    }

    inc_stat(STAT_PASSED);
    return XDP_PASS;
}

static __always_inline int parse_udp_ports(void *data, void *data_end, __u32 l4_off,
                                           struct udphdr **out_udp, __u16 *sport,
                                           __u16 *dport)
{
    struct udphdr *udp = (void *)((char *)data + l4_off);
    if ((void *)(udp + 1) > data_end) {
        inc_stat(STAT_MALFORMED);
        return XDP_PASS;
    }

    *out_udp = udp;
    *sport = bpf_ntohs(udp->source);
    *dport = bpf_ntohs(udp->dest);
    return -1;
}

SEC("xdp/dns4")
int xdp_dns4(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) {
        inc_stat(STAT_MALFORMED);
        return XDP_PASS;
    }

    struct iphdr *ip = 0;
    __u32 l4_off = 0;
    int verdict = validate_ipv4(data, data_end, &ip, &l4_off);
    if (verdict >= 0)
        return verdict;
    if (ip->protocol != IPPROTO_UDP) {
        inc_stat(STAT_PASSED);
        return XDP_PASS;
    }

    struct udphdr *udp = 0;
    __u16 sport = 0, dport = 0;
    verdict = parse_udp_ports(data, data_end, l4_off, &udp, &sport, &dport);
    if (verdict >= 0)
        return verdict;
    if (dport != 53) {
        inc_stat(STAT_PASSED);
        return XDP_PASS;
    }

    return check_dns_v4(data, data_end, eth, ip, udp,
                        l4_off + sizeof(struct udphdr));
}

SEC("xdp/dns6")
int xdp_dns6(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) {
        inc_stat(STAT_MALFORMED);
        return XDP_PASS;
    }

    struct ipv6hdr *ip6 = 0;
    __u32 l4_off = 0;
    int verdict = validate_ipv6(data, data_end, &ip6, &l4_off);
    if (verdict >= 0)
        return verdict;
    if (ip6->nexthdr != IPPROTO_UDP) {
        inc_stat(STAT_PASSED);
        return XDP_PASS;
    }

    struct udphdr *udp = 0;
    __u16 sport = 0, dport = 0;
    verdict = parse_udp_ports(data, data_end, l4_off, &udp, &sport, &dport);
    if (verdict >= 0)
        return verdict;
    if (dport != 53) {
        inc_stat(STAT_PASSED);
        return XDP_PASS;
    }

    return check_dns_v6(data, data_end, eth, ip6, udp, l4_off,
                        l4_off + sizeof(struct udphdr));
}

static __always_inline int validate_ipv4(void *data, void *data_end, struct iphdr **out_ip,
                                         __u32 *out_l4_off)
{
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) {
        inc_stat(STAT_MALFORMED);
        return XDP_PASS;
    }

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end) {
        inc_stat(STAT_MALFORMED);
        return XDP_PASS;
    }

    __u8 ihl = ip->ihl;
    if (ip->version != 4) {
        inc_stat(STAT_MALFORMED);
        return XDP_PASS;
    }

    if (ihl < 5 || ihl > 15) {
        inc_stat(STAT_MALFORMED);
        return XDP_PASS;
    }

    __u32 ip_header_len = (__u32)ihl * 4;
    if ((void *)ip + ip_header_len > data_end) {
        inc_stat(STAT_MALFORMED);
        return XDP_PASS;
    }

    if (ip_matches_cidr(ip->saddr) || ip_matches_cidr(ip->daddr)) {
        inc_stat(STAT_IP_BLOCKED);
        return XDP_DROP;
    }

    __u16 frag_off = bpf_ntohs(ip->frag_off);
    if (frag_off & (IP_MF | IP_OFFSET)) {
        inc_stat(STAT_PASSED);
        return XDP_PASS;
    }

    __u32 l4_off = sizeof(struct ethhdr) + ip_header_len;
    *out_ip = ip;
    *out_l4_off = l4_off;
    return -1;
}

static __always_inline int validate_ipv6(void *data, void *data_end, struct ipv6hdr **out_ip6,
                                         __u32 *out_l4_off)
{
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) {
        inc_stat(STAT_MALFORMED);
        return XDP_PASS;
    }

    struct ipv6hdr *ip6 = (void *)(eth + 1);
    if ((void *)(ip6 + 1) > data_end) {
        inc_stat(STAT_MALFORMED);
        return XDP_PASS;
    }

    if ((ip6->ver_tc_flow[0] >> 4) != 6) {
        inc_stat(STAT_MALFORMED);
        return XDP_PASS;
    }

    if (ip6_matches_cidr(ip6->saddr) || ip6_matches_cidr(ip6->daddr)) {
        inc_stat(STAT_IP_BLOCKED);
        return XDP_DROP;
    }

    *out_ip6 = ip6;
    *out_l4_off = sizeof(struct ethhdr) + sizeof(struct ipv6hdr);
    return -1;
}

SEC("xdp/tcp4")
int xdp_tcp4(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct iphdr *ip = 0;
    __u32 l4_off = 0;
    int verdict = validate_ipv4(data, data_end, &ip, &l4_off);
    if (verdict >= 0)
        return verdict;

    if (ip->protocol != IPPROTO_TCP) {
        inc_stat(STAT_PASSED);
        return XDP_PASS;
    }

    __u32 payload_off = 0;
    __u16 sport = 0, dport = 0;
    verdict = parse_tcp_ports(data, data_end, l4_off, &payload_off, &sport, &dport);
    if (verdict >= 0)
        return verdict;

    if (ip_port_matches(ip->daddr, dport, IPPROTO_TCP) ||
        ip_port_matches(ip->saddr, sport, IPPROTO_TCP)) {
        inc_stat(STAT_IP_PORT_BLOCKED);
        return XDP_DROP;
    }

    if (dport == 80) {
        bpf_tail_call(ctx, &dispatch_rules, DISPATCH_HTTP4);
        inc_stat(STAT_PASSED);
        return XDP_PASS;
    }

    if (dport == 443) {
        bpf_tail_call(ctx, &dispatch_rules, DISPATCH_TLS4);
        inc_stat(STAT_PASSED);
        return XDP_PASS;
    }

    inc_stat(STAT_PASSED);
    return XDP_PASS;
}

SEC("xdp/udp4")
int xdp_udp4(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) {
        inc_stat(STAT_MALFORMED);
        return XDP_PASS;
    }

    struct iphdr *ip = 0;
    __u32 l4_off = 0;
    int verdict = validate_ipv4(data, data_end, &ip, &l4_off);
    if (verdict >= 0)
        return verdict;

    if (ip->protocol != IPPROTO_UDP) {
        inc_stat(STAT_PASSED);
        return XDP_PASS;
    }

    struct udphdr *udp = 0;
    __u16 sport = 0, dport = 0;
    verdict = parse_udp_ports(data, data_end, l4_off, &udp, &sport, &dport);
    if (verdict >= 0)
        return verdict;

    if (ip_port_matches(ip->daddr, dport, IPPROTO_UDP) ||
        ip_port_matches(ip->saddr, sport, IPPROTO_UDP)) {
        inc_stat(STAT_IP_PORT_BLOCKED);
        return XDP_DROP;
    }

    if (dport == 53) {
        bpf_tail_call(ctx, &dispatch_rules, DISPATCH_DNS4);
        inc_stat(STAT_PASSED);
        return XDP_PASS;
    }

    inc_stat(STAT_PASSED);
    return XDP_PASS;
}

SEC("xdp/tcp6")
int xdp_tcp6(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ipv6hdr *ip6 = 0;
    __u32 l4_off = 0;
    int verdict = validate_ipv6(data, data_end, &ip6, &l4_off);
    if (verdict >= 0)
        return verdict;

    if (ip6->nexthdr != IPPROTO_TCP) {
        inc_stat(STAT_PASSED);
        return XDP_PASS;
    }

    __u32 payload_off = 0;
    __u16 sport = 0, dport = 0;
    verdict = parse_tcp_ports(data, data_end, l4_off, &payload_off, &sport, &dport);
    if (verdict >= 0)
        return verdict;

    if (ip6_port_matches(ip6->daddr, dport, IPPROTO_TCP) ||
        ip6_port_matches(ip6->saddr, sport, IPPROTO_TCP)) {
        inc_stat(STAT_IP_PORT_BLOCKED);
        return XDP_DROP;
    }

    if (dport == 80) {
        bpf_tail_call(ctx, &dispatch_rules, DISPATCH_HTTP6);
        inc_stat(STAT_PASSED);
        return XDP_PASS;
    }

    if (dport == 443) {
        bpf_tail_call(ctx, &dispatch_rules, DISPATCH_TLS6);
        inc_stat(STAT_PASSED);
        return XDP_PASS;
    }

    inc_stat(STAT_PASSED);
    return XDP_PASS;
}

SEC("xdp/http4")
int xdp_http4(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct iphdr *ip = 0;
    __u32 l4_off = 0;
    int verdict = validate_ipv4(data, data_end, &ip, &l4_off);
    if (verdict >= 0)
        return verdict;
    if (ip->protocol != IPPROTO_TCP) {
        inc_stat(STAT_PASSED);
        return XDP_PASS;
    }

    __u32 payload_off = 0;
    __u16 sport = 0, dport = 0;
    verdict = parse_tcp_ports(data, data_end, l4_off, &payload_off, &sport, &dport);
    if (verdict >= 0)
        return verdict;
    if (dport != 80) {
        inc_stat(STAT_PASSED);
        return XDP_PASS;
    }

    return run_http_rule(data, data_end, payload_off);
}

SEC("xdp/tls4")
int xdp_tls4(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct iphdr *ip = 0;
    __u32 l4_off = 0;
    int verdict = validate_ipv4(data, data_end, &ip, &l4_off);
    if (verdict >= 0)
        return verdict;
    if (ip->protocol != IPPROTO_TCP) {
        inc_stat(STAT_PASSED);
        return XDP_PASS;
    }

    __u32 payload_off = 0;
    __u16 sport = 0, dport = 0;
    verdict = parse_tcp_ports(data, data_end, l4_off, &payload_off, &sport, &dport);
    if (verdict >= 0)
        return verdict;
    if (dport != 443) {
        inc_stat(STAT_PASSED);
        return XDP_PASS;
    }

    return run_tls_rule(data, data_end, payload_off);
}

SEC("xdp/http6")
int xdp_http6(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ipv6hdr *ip6 = 0;
    __u32 l4_off = 0;
    int verdict = validate_ipv6(data, data_end, &ip6, &l4_off);
    if (verdict >= 0)
        return verdict;
    if (ip6->nexthdr != IPPROTO_TCP) {
        inc_stat(STAT_PASSED);
        return XDP_PASS;
    }

    __u32 payload_off = 0;
    __u16 sport = 0, dport = 0;
    verdict = parse_tcp_ports(data, data_end, l4_off, &payload_off, &sport, &dport);
    if (verdict >= 0)
        return verdict;
    if (dport != 80) {
        inc_stat(STAT_PASSED);
        return XDP_PASS;
    }

    return run_http_rule(data, data_end, payload_off);
}

SEC("xdp/tls6")
int xdp_tls6(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ipv6hdr *ip6 = 0;
    __u32 l4_off = 0;
    int verdict = validate_ipv6(data, data_end, &ip6, &l4_off);
    if (verdict >= 0)
        return verdict;
    if (ip6->nexthdr != IPPROTO_TCP) {
        inc_stat(STAT_PASSED);
        return XDP_PASS;
    }

    __u32 payload_off = 0;
    __u16 sport = 0, dport = 0;
    verdict = parse_tcp_ports(data, data_end, l4_off, &payload_off, &sport, &dport);
    if (verdict >= 0)
        return verdict;
    if (dport != 443) {
        inc_stat(STAT_PASSED);
        return XDP_PASS;
    }

    return run_tls_rule(data, data_end, payload_off);
}

SEC("xdp/udp6")
int xdp_udp6(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) {
        inc_stat(STAT_MALFORMED);
        return XDP_PASS;
    }

    struct ipv6hdr *ip6 = 0;
    __u32 l4_off = 0;
    int verdict = validate_ipv6(data, data_end, &ip6, &l4_off);
    if (verdict >= 0)
        return verdict;

    if (ip6->nexthdr != IPPROTO_UDP) {
        inc_stat(STAT_PASSED);
        return XDP_PASS;
    }

    struct udphdr *udp = 0;
    __u16 sport = 0, dport = 0;
    verdict = parse_udp_ports(data, data_end, l4_off, &udp, &sport, &dport);
    if (verdict >= 0)
        return verdict;

    if (ip6_port_matches(ip6->daddr, dport, IPPROTO_UDP) ||
        ip6_port_matches(ip6->saddr, sport, IPPROTO_UDP)) {
        inc_stat(STAT_IP_PORT_BLOCKED);
        return XDP_DROP;
    }

    if (dport == 53) {
        bpf_tail_call(ctx, &dispatch_rules, DISPATCH_DNS6);
        inc_stat(STAT_PASSED);
        return XDP_PASS;
    }

    inc_stat(STAT_PASSED);
    return XDP_PASS;
}

SEC("xdp/ipv4")
int xdp_ipv4(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct iphdr *ip = 0;
    __u32 l4_off = 0;
    int verdict = validate_ipv4(data, data_end, &ip, &l4_off);
    if (verdict >= 0)
        return verdict;

    if (ip->protocol == IPPROTO_TCP) {
        bpf_tail_call(ctx, &dispatch_rules, DISPATCH_TCP4);
        inc_stat(STAT_PASSED);
        return XDP_PASS;
    }

    if (ip->protocol == IPPROTO_UDP) {
        bpf_tail_call(ctx, &dispatch_rules, DISPATCH_UDP4);
        inc_stat(STAT_PASSED);
        return XDP_PASS;
    }

    inc_stat(STAT_PASSED);
    return XDP_PASS;
}

SEC("xdp/ipv6")
int xdp_ipv6(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ipv6hdr *ip6 = 0;
    __u32 l4_off = 0;
    int verdict = validate_ipv6(data, data_end, &ip6, &l4_off);
    if (verdict >= 0)
        return verdict;

    if (ip6->nexthdr == IPPROTO_TCP) {
        bpf_tail_call(ctx, &dispatch_rules, DISPATCH_TCP6);
        inc_stat(STAT_PASSED);
        return XDP_PASS;
    }

    if (ip6->nexthdr == IPPROTO_UDP) {
        bpf_tail_call(ctx, &dispatch_rules, DISPATCH_UDP6);
        inc_stat(STAT_PASSED);
        return XDP_PASS;
    }

    inc_stat(STAT_PASSED);
    return XDP_PASS;
}

SEC("xdp")
int xdp_filter(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    inc_stat(STAT_TOTAL);

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) {
        inc_stat(STAT_MALFORMED);
        return XDP_PASS;
    }

    if (eth->h_proto == bpf_htons(ETH_P_IP)) {
        bpf_tail_call(ctx, &dispatch_rules, DISPATCH_IPV4);
        inc_stat(STAT_PASSED);
        return XDP_PASS;
    }

    if (eth->h_proto == bpf_htons(ETH_P_IPV6)) {
        bpf_tail_call(ctx, &dispatch_rules, DISPATCH_IPV6);
        inc_stat(STAT_PASSED);
        return XDP_PASS;
    }

    inc_stat(STAT_PASSED);
    return XDP_PASS;
}
