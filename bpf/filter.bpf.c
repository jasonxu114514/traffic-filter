// filter.bpf.c - XDP Traffic Filter with Domain Filtering
// Features: HTTP Host, TLS SNI, DNS detection and poisoning, Port blocking
// Compile: clang -O2 -g -target bpf -c filter.bpf.c -o filter.bpf.o

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

char LICENSE[] SEC("license") = "GPL";

#define MAX_DOMAIN_LEN 128

// ─── Configuration ───────────────────────────────────────────────────────
struct config {
    __u32 dns_mode;  // 0 = DROP, 1 = POISON
};

// ─── Maps ────────────────────────────────────────────────────────────────

// Map: blocked domains (key=domain as fixed-size array, value=1)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 128);
    __type(key, char[MAX_DOMAIN_LEN]);
    __type(value, __u8);
} blocked_domains SEC(".maps");

// Map: blocked ports (key=port as u16, value=1)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u16);
    __type(value, __u8);
} blocked_ports SEC(".maps");

// Map: configuration
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct config);
} config_map SEC(".maps");

// Map: statistics
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 10);
    __type(key, __u32);
    __type(value, __u64);
} stats SEC(".maps");

// ─── Statistics Indices ──────────────────────────────────────────────────
#define STAT_TOTAL 0
#define STAT_BLOCKED 1
#define STAT_PASSED 2
#define STAT_HTTP 3
#define STAT_TLS 4
#define STAT_DNS 5
#define STAT_DNS_POISONED 6

// ─── Helper Functions ────────────────────────────────────────────────────

static __always_inline void inc_stat(__u32 key) {
    __u64 *val = bpf_map_lookup_elem(&stats, &key);
    if (val) {
        __sync_fetch_and_add(val, 1);
    }
}

static __always_inline struct config *get_config(void) {
    __u32 key = 0;
    return bpf_map_lookup_elem(&config_map, &key);
}

// Check if a domain is blocked
static __always_inline int is_domain_blocked(char *domain, int len, void *data_end) {
    char key[MAX_DOMAIN_LEN] = {};

    // Limit length
    if (len > MAX_DOMAIN_LEN - 1) len = MAX_DOMAIN_LEN - 1;

    // Copy domain to fixed-size key (limited to 64 bytes to reduce instructions)
    #pragma unroll
    for (int i = 0; i < 64; i++) {
        if (i >= len) break;
        if (domain + i >= (char *)data_end) break;
        key[i] = domain[i];
    }

    __u8 *val = bpf_map_lookup_elem(&blocked_domains, key);
    return (val != NULL && *val == 1);
}

// ─── DNS Name Parsing ────────────────────────────────────────────────────

// Parse DNS label format to text (e.g., \x07example\x03com\x00 -> example.com)
static __always_inline int parse_dns_name(char *in, char *out, void *data_end) {
    int pos = 0, out_pos = 0;

    #pragma unroll
    for (int i = 0; i < 32; i++) {  // Reduced from 64
        if (in + pos >= (char *)data_end) break;

        __u8 len = in[pos];
        if (len == 0) break;  // End of name
        if (len >= 192) return -1;  // Compressed (not supported in simple version)
        if (len > 63) return -1;  // Invalid label

        pos++;

        // Add dot separator (except for first label)
        if (out_pos > 0 && out_pos < MAX_DOMAIN_LEN - 1) {
            out[out_pos++] = '.';
        }

        // Copy label (reduced to 32 to save instructions)
        #pragma unroll
        for (int j = 0; j < 32; j++) {  // Reduced from 63
            if (j >= len || out_pos >= MAX_DOMAIN_LEN - 1) break;
            if (in + pos >= (char *)data_end) return -1;
            out[out_pos++] = in[pos++];
        }
    }

    return out_pos;
}

// ─── DNS Header ──────────────────────────────────────────────────────────

struct dnshdr {
    __u16 id;
    __u16 flags;
    __u16 qdcount;
    __u16 ancount;
    __u16 nscount;
    __u16 arcount;
} __attribute__((packed));

// ─── DNS Poisoning ───────────────────────────────────────────────────────

static __always_inline int poison_dns_response(struct xdp_md *ctx,
    struct ethhdr *eth, struct iphdr *ip, struct udphdr *udp, struct dnshdr *dns) {

    // Swap Ethernet MAC (direct assignment to avoid memcpy)
    __u8 tmp_mac[6];
    tmp_mac[0] = eth->h_source[0]; tmp_mac[1] = eth->h_source[1];
    tmp_mac[2] = eth->h_source[2]; tmp_mac[3] = eth->h_source[3];
    tmp_mac[4] = eth->h_source[4]; tmp_mac[5] = eth->h_source[5];

    eth->h_source[0] = eth->h_dest[0]; eth->h_source[1] = eth->h_dest[1];
    eth->h_source[2] = eth->h_dest[2]; eth->h_source[3] = eth->h_dest[3];
    eth->h_source[4] = eth->h_dest[4]; eth->h_source[5] = eth->h_dest[5];

    eth->h_dest[0] = tmp_mac[0]; eth->h_dest[1] = tmp_mac[1];
    eth->h_dest[2] = tmp_mac[2]; eth->h_dest[3] = tmp_mac[3];
    eth->h_dest[4] = tmp_mac[4]; eth->h_dest[5] = tmp_mac[5];

    // Swap IP addresses
    __u32 tmp_ip = ip->saddr;
    ip->saddr = ip->daddr;
    ip->daddr = tmp_ip;

    // Swap UDP ports
    __u16 tmp_port = udp->source;
    udp->source = udp->dest;
    udp->dest = tmp_port;

    // Modify DNS flags: QR=1 (response), RCODE=3 (NXDOMAIN)
    dns->flags = bpf_htons(0x8183);

    // Clear IP and UDP checksums (often acceptable, especially with offload)
    ip->check = 0;
    udp->check = 0;

    inc_stat(STAT_DNS_POISONED);
    inc_stat(STAT_BLOCKED);

    return XDP_TX;  // Send it back
}

// ─── DNS Detection ───────────────────────────────────────────────────────

static __always_inline int check_dns(struct xdp_md *ctx, void *data, void *data_end,
    __u32 off, struct ethhdr *eth, struct iphdr *ip, struct udphdr *udp) {

    struct dnshdr *dns = (void *)data + off;
    if ((void *)(dns + 1) > data_end) return XDP_PASS;

    inc_stat(STAT_DNS);

    // Only process queries (QR=0)
    if (bpf_ntohs(dns->flags) & 0x8000) return XDP_PASS;
    if (bpf_ntohs(dns->qdcount) == 0) return XDP_PASS;

    // Parse domain name
    char *qname = (char *)(dns + 1);
    if (qname >= (char *)data_end) return XDP_PASS;

    char domain[MAX_DOMAIN_LEN] = {};
    int dlen = parse_dns_name(qname, domain, data_end);
    if (dlen <= 0) return XDP_PASS;

    // Check if domain is blocked
    if (!is_domain_blocked(domain, dlen, data_end)) return XDP_PASS;

    // Get configuration
    struct config *cfg = get_config();
    if (!cfg || cfg->dns_mode == 0) {
        // DROP mode
        inc_stat(STAT_BLOCKED);
        return XDP_DROP;
    }

    // POISON mode
    return poison_dns_response(ctx, eth, ip, udp, dns);
}

// ─── HTTP Host Detection ─────────────────────────────────────────────────

static __always_inline int check_http_host(void *data, void *data_end, __u32 off) {
    char *p = (char *)data + off;

    // Check we have enough data for HTTP method
    if (p + 16 > (char *)data_end) return XDP_PASS;

    // Check for GET/POST/PUT/HEAD methods
    int is_http = 0;
    if (p[0]=='G' && p[1]=='E' && p[2]=='T' && p[3]==' ') is_http = 1;
    if (p[0]=='P' && p[1]=='O' && p[2]=='S' && p[3]=='T') is_http = 1;
    if (p[0]=='P' && p[1]=='U' && p[2]=='T' && p[3]==' ') is_http = 1;
    if (p[0]=='H' && p[1]=='E' && p[2]=='A' && p[3]=='D') is_http = 1;

    if (!is_http) return XDP_PASS;

    inc_stat(STAT_HTTP);

    // Search for "Host: " header (limited to 128 bytes, 16 iterations)
    #pragma unroll
    for (int i = 0; i < 16; i++) {  // Reduced from 32
        int offset = i * 8;
        if (p + offset + 6 > (char *)data_end) break;

        if (p[offset]=='H' && p[offset+1]=='o' && p[offset+2]=='s' &&
            p[offset+3]=='t' && p[offset+4]==':' && p[offset+5]==' ') {

            // Found "Host: ", extract domain
            char *host = p + offset + 6;
            int host_len = 0;

            // Find end of host (CR/LF/space) - reduced to 64 iterations
            #pragma unroll
            for (int j = 0; j < 64; j++) {  // Reduced from MAX_DOMAIN_LEN
                if (host + j >= (char *)data_end) break;
                if (host[j]=='\r' || host[j]=='\n' || host[j]==' ') {
                    host_len = j;
                    break;
                }
            }

            if (host_len > 0 && is_domain_blocked(host, host_len, data_end)) {
                inc_stat(STAT_BLOCKED);
                return XDP_DROP;
            }
            break;
        }
    }

    return XDP_PASS;
}

// ─── TLS SNI Detection ───────────────────────────────────────────────────

static __always_inline int check_tls_sni(void *data, void *data_end, __u32 off) {
    char *p = (char *)data + off;

    // TLS Record Header (5 bytes): Content Type + Version + Length
    if (p + 5 > (char *)data_end) return XDP_PASS;
    if (p[0] != 0x16) return XDP_PASS;  // Not Handshake
    if (p[1] != 0x03) return XDP_PASS;  // Not TLS

    // Handshake Type (1 byte): must be ClientHello (0x01)
    if (p + 6 > (char *)data_end) return XDP_PASS;
    if (p[5] != 0x01) return XDP_PASS;

    inc_stat(STAT_TLS);

    // Skip: Handshake Length (3) + Version (2) + Random (32) = 37 bytes
    // So position is now at byte 43 (5 + 1 + 37)
    __u32 pos = 43;

    // Session ID: 1 byte length + N bytes
    if (p + pos + 1 > (char *)data_end) return XDP_PASS;
    __u8 session_id_len = p[pos];
    pos += 1 + session_id_len;

    // Cipher Suites: 2 bytes length + N bytes
    if (p + pos + 2 > (char *)data_end) return XDP_PASS;
    __u16 cipher_suites_len = (p[pos] << 8) | p[pos + 1];
    pos += 2 + cipher_suites_len;

    // Compression Methods: 1 byte length + N bytes
    if (p + pos + 1 > (char *)data_end) return XDP_PASS;
    __u8 compression_len = p[pos];
    pos += 1 + compression_len;

    // Extensions Length: 2 bytes
    if (p + pos + 2 > (char *)data_end) return XDP_PASS;
    pos += 2;

    // Iterate through extensions (limit to 12 instead of 16)
    #pragma unroll
    for (int i = 0; i < 12; i++) {
        if (p + pos + 4 > (char *)data_end) break;

        __u16 ext_type = (p[pos] << 8) | p[pos + 1];
        __u16 ext_len = (p[pos + 2] << 8) | p[pos + 3];
        pos += 4;

        if (ext_type == 0x0000) {  // SNI Extension
            // SNI List Length (2) + Name Type (1) + Name Length (2)
            if (p + pos + 5 > (char *)data_end) break;

            __u16 name_len = (p[pos + 3] << 8) | p[pos + 4];
            pos += 5;

            // Check domain
            if (p + pos + name_len > (char *)data_end) break;
            if (is_domain_blocked(p + pos, name_len, data_end)) {
                inc_stat(STAT_BLOCKED);
                return XDP_DROP;
            }
            break;
        }

        pos += ext_len;
        if (pos >= 512) break;  // Safety: don't parse too far
    }

    return XDP_PASS;
}

// ─── XDP Main Entry Point ───────────────────────────────────────────────

SEC("xdp")
int xdp_filter(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    inc_stat(STAT_TOTAL);

    // Parse Ethernet header
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    // Only process IPv4
    if (eth->h_proto != bpf_htons(0x0800))
        return XDP_PASS;

    // Parse IP header
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    __u8 protocol = ip->protocol;

    // ═══ TCP Processing ═══
    if (protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (void *)ip + (ip->ihl * 4);
        if ((void *)(tcp + 1) > data_end)
            return XDP_PASS;

        __u16 dst_port = bpf_ntohs(tcp->dest);

        // Check port blocking first
        __u8 *blocked = bpf_map_lookup_elem(&blocked_ports, &dst_port);
        if (blocked && *blocked) {
            inc_stat(STAT_BLOCKED);
            return XDP_DROP;
        }

        // L7 filtering
        __u32 tcp_header_len = tcp->doff * 4;
        __u32 payload_offset = sizeof(struct ethhdr) + (ip->ihl * 4) + tcp_header_len;

        if (dst_port == 80) {
            // HTTP Host detection
            return check_http_host(data, data_end, payload_offset);
        }
        else if (dst_port == 443) {
            // TLS SNI detection
            return check_tls_sni(data, data_end, payload_offset);
        }
    }
    // ═══ UDP Processing ═══
    else if (protocol == IPPROTO_UDP) {
        struct udphdr *udp = (void *)ip + (ip->ihl * 4);
        if ((void *)(udp + 1) > data_end)
            return XDP_PASS;

        __u16 dst_port = bpf_ntohs(udp->dest);

        // Check port blocking first
        __u8 *blocked = bpf_map_lookup_elem(&blocked_ports, &dst_port);
        if (blocked && *blocked) {
            inc_stat(STAT_BLOCKED);
            return XDP_DROP;
        }

        // DNS filtering
        if (dst_port == 53) {
            __u32 payload_offset = sizeof(struct ethhdr) + (ip->ihl * 4) + sizeof(struct udphdr);
            return check_dns(ctx, data, data_end, payload_offset, eth, ip, udp);
        }
    }

    inc_stat(STAT_PASSED);
    return XDP_PASS;
}

