// filter.bpf.c - Simple SNI/Host filter
// Just parse packets, check domain, drop if blocked

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

char LICENSE[] SEC("license") = "GPL";

#define MAX_DOMAIN_LEN 64

// Map: blocked domains
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 128);
    __type(key, char[MAX_DOMAIN_LEN]);
    __type(value, __u8);
} blocked_domains SEC(".maps");

// Stats
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 4);
    __type(key, __u32);
    __type(value, __u64);
} stats SEC(".maps");

#define STAT_TOTAL 0
#define STAT_BLOCKED 1
#define STAT_PASSED 2

static __always_inline void inc_stat(__u32 key) {
    __u64 *val = bpf_map_lookup_elem(&stats, &key);
    if (val) __sync_fetch_and_add(val, 1);
}

// Check domain
static __always_inline int check_domain(void *data, void *data_end, char *domain_start, int domain_len) {
    if (domain_len <= 0 || domain_len > MAX_DOMAIN_LEN) return 0;
    if (domain_start + domain_len > (char *)data_end) return 0;

    char key[MAX_DOMAIN_LEN] = {};

    // Simple copy without pragma unroll
    for (int i = 0; i < MAX_DOMAIN_LEN && i < domain_len; i++) {
        if (domain_start + i >= (char *)data_end) break;
        key[i] = domain_start[i];
    }

    __u8 *val = bpf_map_lookup_elem(&blocked_domains, key);
    return (val && *val == 1);
}

// Check HTTP Host
static __always_inline int check_http(void *data, void *data_end, void *payload) {
    char *p = (char *)payload;

    // Check method
    if (p + 4 > (char *)data_end) return XDP_PASS;
    if (!(p[0]=='G' && p[1]=='E' && p[2]=='T' && p[3]==' ')) return XDP_PASS;

    // Find Host:
    for (int i = 0; i < 200; i++) {
        if (p + i + 6 > (char *)data_end) break;
        if (p[i]=='H' && p[i+1]=='o' && p[i+2]=='s' && p[i+3]=='t' && p[i+4]==':' && p[i+5]==' ') {
            char *host = p + i + 6;

            // Find end
            for (int j = 0; j < MAX_DOMAIN_LEN; j++) {
                if (host + j >= (char *)data_end) break;
                if (host[j]=='\r' || host[j]=='\n' || host[j]==' ') {
                    if (check_domain(data, data_end, host, j)) {
                        inc_stat(STAT_BLOCKED);
                        return XDP_DROP;
                    }
                    return XDP_PASS;
                }
            }
            break;
        }
    }
    return XDP_PASS;
}

// Check TLS SNI
static __always_inline int check_tls(void *data, void *data_end, void *payload) {
    char *p = (char *)payload;

    // TLS handshake check
    if (p + 6 > (char *)data_end) return XDP_PASS;
    if (p[0] != 0x16 || p[1] != 0x03 || p[5] != 0x01) return XDP_PASS;

    // Skip to extensions
    int pos = 43; // Fixed offset to session ID

    // Session ID
    if (p + pos + 1 > (char *)data_end) return XDP_PASS;
    pos += 1 + p[pos];

    // Cipher suites
    if (p + pos + 2 > (char *)data_end) return XDP_PASS;
    pos += 2 + ((p[pos] << 8) | p[pos + 1]);

    // Compression
    if (p + pos + 1 > (char *)data_end) return XDP_PASS;
    pos += 1 + p[pos];

    // Extensions length
    if (p + pos + 2 > (char *)data_end) return XDP_PASS;
    pos += 2;

    // Find SNI
    for (int i = 0; i < 10; i++) {
        if (p + pos + 4 > (char *)data_end) break;

        __u16 ext_type = (p[pos] << 8) | p[pos + 1];
        __u16 ext_len = (p[pos + 2] << 8) | p[pos + 3];
        pos += 4;

        if (ext_type == 0) { // SNI
            if (p + pos + 5 > (char *)data_end) break;
            __u16 name_len = (p[pos + 3] << 8) | p[pos + 4];
            pos += 5;

            if (p + pos + name_len > (char *)data_end) break;
            if (check_domain(data, data_end, p + pos, name_len)) {
                inc_stat(STAT_BLOCKED);
                return XDP_DROP;
            }
            return XDP_PASS;
        }
        pos += ext_len;
    }
    return XDP_PASS;
}

SEC("xdp")
int xdp_filter(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    inc_stat(STAT_TOTAL);

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) return XDP_PASS;
    if (eth->h_proto != bpf_htons(0x0800)) return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end) return XDP_PASS;

    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (void *)ip + (ip->ihl * 4);
        if ((void *)(tcp + 1) > data_end) return XDP_PASS;

        void *payload = (void *)tcp + (tcp->doff * 4);
        if (payload >= data_end) return XDP_PASS;

        __u16 dport = bpf_ntohs(tcp->dest);

        int result = XDP_PASS;
        if (dport == 80) result = check_http(data, data_end, payload);
        else if (dport == 443) result = check_tls(data, data_end, payload);

        if (result == XDP_PASS) inc_stat(STAT_PASSED);
        return result;
    }

    inc_stat(STAT_PASSED);
    return XDP_PASS;
}
