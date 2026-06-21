// filter.bpf.c - Simplified XDP filter (no complex packet parsing)
// This version only checks port numbers and uses BPF maps for decisions

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

char LICENSE[] SEC("license") = "GPL";

// Map: blocked ports (key=port, value=1)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u16);
    __type(value, __u8);
} blocked_ports SEC(".maps");

// Statistics
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
    if (val) {
        __sync_fetch_and_add(val, 1);
    }
}

SEC("xdp")
int xdp_filter(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    inc_stat(STAT_TOTAL);

    // Ethernet header
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    // Only IPv4
    if (eth->h_proto != bpf_htons(0x0800))
        return XDP_PASS;

    // IP header
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    __u8 proto = ip->protocol;
    __u32 ihl = ip->ihl * 4;

    __u16 dport = 0;

    // TCP
    if (proto == 6) {
        struct tcphdr *tcp = (void *)ip + ihl;
        if ((void *)(tcp + 1) > data_end)
            return XDP_PASS;
        dport = bpf_ntohs(tcp->dest);
    }
    // UDP
    else if (proto == 17) {
        struct udphdr *udp = (void *)ip + ihl;
        if ((void *)(udp + 1) > data_end)
            return XDP_PASS;
        dport = bpf_ntohs(udp->dest);
    }
    else {
        return XDP_PASS;
    }

    // Check if port is blocked
    __u8 *blocked = bpf_map_lookup_elem(&blocked_ports, &dport);
    if (blocked && *blocked) {
        inc_stat(STAT_BLOCKED);
        return XDP_DROP;
    }

    inc_stat(STAT_PASSED);
    return XDP_PASS;
}
