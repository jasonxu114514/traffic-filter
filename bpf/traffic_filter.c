// traffic_filter.c - eBPF/XDP 程序
// 支持: HTTP Host / TLS SNI / DNS 域名阻斷 + IP 阻斷 + IP:Port 阻斷 + TCP RST 注入
// 編譯: clang -O2 -target bpf -c traffic_filter.c -o traffic_filter.o

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define MAX_BLOCKED_DOMAINS  128
#define MAX_DOMAIN_LEN       128
#define MAX_BLOCKED_IPS      256
#define MAX_BLOCKED_IP_PORTS 512
#define DNS_POISON_IP        0x00000000  // 0.0.0.0

// ─── 配置 ───────────────────────────────────────────────────────────────
struct config {
    __u32 dns_mode;      // 0 = DROP, 1 = POISON
    __u32 ip_mode;       // bitmask: bit0=TCP, bit1=UDP, bit2=ICMP (default 7=all)
    __u32 ip_port_mask;  // bitmask: bit0=TCP, bit1=UDP (default 3=all)
};
static struct config DEFAULT_CONFIG = {
    .dns_mode = 0,
    .ip_mode  = 7,   // TCP | UDP | ICMP
    .ip_port_mask = 3, // TCP | UDP
};

// ─── Maps ────────────────────────────────────────────────────────────────

// 阻斷域名列表
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_BLOCKED_DOMAINS);
    __type(key, char[MAX_DOMAIN_LEN]);
    __type(value, __u32);
} blocked_domains SEC(".maps");

// 阻斷 IP 列表 (key = IPv4 addr in network order)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_BLOCKED_IPS);
    __type(key, __u32);
    __type(value, __u32);
} blocked_ips SEC(".maps");

// 阻斷 IP:Port 組合 key = {ip(4), port(2), proto(1), pad(1)}
struct ip_port_key {
    __u32 ip;
    __u16 port;
    __u8  proto;
    __u8  pad;
};
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_BLOCKED_IP_PORTS);
    __type(key, struct ip_port_key);
    __type(value, __u32);
} blocked_ip_ports SEC(".maps");

// 配置
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct config);
} config_map SEC(".maps");

// 統計 - 擴展為 8 個條目
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 8);
    __type(key, __u32);
    __type(value, __u64);
} stats SEC(".maps");

// ─── 統計索引 ────────────────────────────────────────────────────────────
enum {
    STAT_TOTAL_PACKETS = 0,
    STAT_BLOCKED_PACKETS = 1,
    STAT_HTTP_PACKETS = 2,
    STAT_TLS_PACKETS = 3,
    STAT_DNS_PACKETS = 4,
    STAT_IP_BLOCKED = 5,
    STAT_IP_PORT_BLOCKED = 6,
    STAT_RST_SENT = 7,
};

// ─── 輔助函數 ───────────────────────────────────────────────────────────

static __always_inline void increment_stat(__u32 key) {
    __u64 *v = bpf_map_lookup_elem(&stats, &key);
    if (v) __sync_fetch_and_add(v, 1);
}

static __always_inline struct config *get_config(void) {
    __u32 k = 0;
    struct config *c = bpf_map_lookup_elem(&config_map, &k);
    return c ? c : &DEFAULT_CONFIG;
}

// IP/TCP 校驗和 (RFC 1071 folding)
static __always_inline __u16 fold_csum(__u32 sum) {
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum = (sum >> 16) + (sum & 0xFFFF);
    return ~sum;
}

static __always_inline __u16 ip_csum(void *hdr, int words) {
    __u32 sum = 0;
    __u16 *p = (__u16 *)hdr;
#pragma unroll
    for (int i = 0; i < 10; i++) {
        if (i >= words) break;
        sum += p[i];
    }
    return fold_csum(sum);
}

// 計算 TCP 偽頭部校驗和 (用於 TCP checksum)
static __always_inline __u16 tcp_pseudo_csum(__u32 saddr, __u32 daddr,
                                              __u16 tcplen) {
    __u32 sum = 0;
    sum += (saddr >> 16) & 0xFFFF;
    sum += saddr & 0xFFFF;
    sum += (daddr >> 16) & 0xFFFF;
    sum += daddr & 0xFFFF;
    sum += bpf_htons(IPPROTO_TCP);
    sum += tcplen;
    return (__u16)(sum & 0xFFFF) + (__u16)(sum >> 16);
}

// 輔助函數：內存拷貝 (手動循環避免 bpf_probe_read 在 XDP 中的限制)
static __always_inline void mem_cpy(void *dst, void *src, int n) {
#pragma unroll
    for (int i = 0; i < 128; i++) {
        if (i >= n) break;
        ((char *)dst)[i] = ((char *)src)[i];
    }
}

// ─── 域名檢查 ───────────────────────────────────────────────────────────

static __always_inline int is_domain_blocked(char *domain, int len) {
    if (len > MAX_DOMAIN_LEN) len = MAX_DOMAIN_LEN;
    char buf[MAX_DOMAIN_LEN] = {};
#pragma unroll
    for (int i = 0; i < MAX_DOMAIN_LEN && i < len; i++)
        buf[i] = domain[i];

    return bpf_map_lookup_elem(&blocked_domains, buf) != NULL;
}

// ─── DNS 域名解析 (標籤格式 → 域名文本) ──────────────────────────────────

static __always_inline int parse_dns_name(char *in, char *out, void *data_end) {
    int pos = 0, out_pos = 0;
#pragma unroll
    for (int i = 0; i < 64; i++) {
        if (in + pos >= (char *)data_end) break;
        __u8 len = in[pos];
        if (len == 0) break;
        if (len >= 192) return -1;
        if (len > 63) return -1;
        pos++;
        if (out_pos > 0 && out_pos < MAX_DOMAIN_LEN - 1)
            out[out_pos++] = '.';
#pragma unroll
        for (int j = 0; j < 63; j++) {
            if (j >= len || out_pos >= MAX_DOMAIN_LEN - 1) break;
            if (in + pos >= (char *)data_end) return -1;
            out[out_pos++] = in[pos++];
        }
    }
    return out_pos;
}

// ─── DNS 污染 ────────────────────────────────────────────────────────────

struct dnshdr {
    __u16 id, flags, qdcount, ancount, nscount, arcount;
} __attribute__((packed));

static __always_inline int poison_dns_response(struct xdp_md *ctx,
    struct ethhdr *eth, struct iphdr *ip, struct udphdr *udp, struct dnshdr *dns) {

    // Swap MAC
    __u8 tmp[6];
    mem_cpy(tmp, eth->h_source, 6);
    mem_cpy(eth->h_source, eth->h_dest, 6);
    mem_cpy(eth->h_dest, tmp, 6);

    // Swap IP
    __u32 tip = ip->saddr; ip->saddr = ip->daddr; ip->daddr = tip;

    // Swap port
    __u16 tp = udp->source; udp->source = udp->dest; udp->dest = tp;

    // DNS: response + NXDOMAIN (RCODE=3)
    dns->flags = bpf_htons(0x8183);

    // Adjust lengths
    __u16 dns_len = bpf_ntohs(udp->len) - sizeof(struct udphdr);
    ip->tot_len = bpf_htons(sizeof(struct iphdr) + sizeof(struct udphdr) + dns_len);
    udp->len   = bpf_htons(sizeof(struct udphdr) + dns_len);

    // Recalc checksums
    ip->check = 0;
    ip->check = ip_csum(ip, sizeof(struct iphdr) / 2);
    udp->check = 0;

    return XDP_TX;
}

static __always_inline int check_dns(struct xdp_md *ctx, void *data, void *data_end,
                                      __u32 off, struct ethhdr *eth, struct iphdr *ip,
                                      struct udphdr *udp) {
    struct dnshdr *dns = (void *)data + off;
    if ((void *)(dns + 1) > data_end) return XDP_PASS;
    increment_stat(STAT_DNS_PACKETS);

    if (bpf_ntohs(dns->flags) & 0x8000) return XDP_PASS;  // response, pass
    if (bpf_ntohs(dns->qdcount) == 0) return XDP_PASS;

    char *qname = (char *)(dns + 1);
    if (qname >= (char *)data_end) return XDP_PASS;

    char domain[MAX_DOMAIN_LEN] = {};
    int dlen = parse_dns_name(qname, domain, data_end);
    if (dlen <= 0) return XDP_PASS;

    if (is_domain_blocked(domain, dlen)) {
        increment_stat(STAT_BLOCKED_PACKETS);
        struct config *cfg = get_config();
        if (cfg && cfg->dns_mode == 1)
            return poison_dns_response(ctx, eth, ip, udp, dns);
        return XDP_DROP;
    }
    return XDP_PASS;
}

// ─── HTTP 檢測 ───────────────────────────────────────────────────────────

static __always_inline int check_http_host(void *data, void *data_end, __u32 off) {
    char *p = (char *)data + off;
    if (p + 16 > (char *)data_end) return XDP_PASS;

    if (!((p[0]=='G' && p[1]=='E' && p[2]=='T')  ||
          (p[0]=='P' && p[1]=='O' && p[2]=='S' && p[3]=='T') ||
          (p[0]=='P' && p[1]=='U' && p[2]=='T')  ||
          (p[0]=='H' && p[1]=='E' && p[2]=='A' && p[3]=='D')))
        return XDP_PASS;

    increment_stat(STAT_HTTP_PACKETS);

#pragma unroll
    for (int i = 0; i < 512; i++) {
        if (p + i + 6 > (char *)data_end) break;
        if (p[i]=='H' && p[i+1]=='o' && p[i+2]=='s' && p[i+3]=='t' &&
            p[i+4]==':' && p[i+5]==' ') {
            char *hs = p + i + 6;
            int hl = 0;
#pragma unroll
            for (int j = 0; j < MAX_DOMAIN_LEN; j++) {
                if (hs + j >= (char *)data_end) break;
                if (hs[j]=='\r' || hs[j]=='\n' || hs[j]==' ') { hl = j; break; }
            }
            if (hl > 0 && is_domain_blocked(hs, hl)) {
                increment_stat(STAT_BLOCKED_PACKETS);
                return XDP_DROP;
            }
            break;
        }
    }
    return XDP_PASS;
}

// ─── TLS SNI 檢測 ────────────────────────────────────────────────────────

static __always_inline int check_tls_sni(void *data, void *data_end, __u32 off) {
    char *p = (char *)data + off;
    if (p + 9 > (char *)data_end) return XDP_PASS;
    if (p[0] != 0x16 || p[1] != 0x03) return XDP_PASS;
    if (p[5] != 0x01) return XDP_PASS;  // not ClientHello

    increment_stat(STAT_TLS_PACKETS);

    __u32 pos = 43;
    if (p + pos + 1 > (char *)data_end) return XDP_PASS;
    pos += 1 + (__u8)p[pos];  // session id

    if (p + pos + 2 > (char *)data_end) return XDP_PASS;
    pos += 2 + ((p[pos]<<8) | p[pos+1]);  // cipher suites

    if (p + pos + 1 > (char *)data_end) return XDP_PASS;
    pos += 1 + (__u8)p[pos];  // compression

    if (p + pos + 2 > (char *)data_end) return XDP_PASS;
    __u16 elen = (p[pos]<<8) | p[pos+1];
    pos += 2;

#pragma unroll
    for (int i = 0; i < 20; i++) {
        if (p + pos + 4 > (char *)data_end) break;
        __u16 etype = (p[pos]<<8) | p[pos+1];
        __u16 etlen = (p[pos+2]<<8) | p[pos+3];
        pos += 4;

        if (etype == 0x0000) {  // SNI
            if (p + pos + 5 > (char *)data_end) break;
            __u16 slen = (p[pos+3]<<8) | p[pos+4];
            pos += 5;
            if (p + pos + slen > (char *)data_end || slen > MAX_DOMAIN_LEN) break;
            if (is_domain_blocked(p + pos, slen)) {
                increment_stat(STAT_BLOCKED_PACKETS);
                return XDP_DROP;
            }
            break;
        }
        pos += etlen;
        if (pos >= 512) break;
    }
    return XDP_PASS;
}

// ─── TCP RST 注入 ────────────────────────────────────────────────────────

static __always_inline int send_tcp_rst(struct xdp_md *ctx,
    struct ethhdr *eth, struct iphdr *ip, struct tcphdr *tcp) {

    __u32 tcp_off = tcp->doff * 4;
    __u32 ip_len  = bpf_ntohs(ip->tot_len);
    __u32 tcp_len = ip_len - (ip->ihl * 4);

    // Swap MAC
    __u8 tmp[6];
    mem_cpy(tmp, eth->h_source, 6);
    mem_cpy(eth->h_source, eth->h_dest, 6);
    mem_cpy(eth->h_dest, tmp, 6);

    // Swap IP
    __u32 orig_saddr = ip->saddr;
    __u32 orig_daddr = ip->daddr;
    ip->saddr = orig_daddr;
    ip->daddr = orig_saddr;

    // Build RST
    __u16 orig_src  = tcp->source;
    __u16 orig_dst  = tcp->dest;
    __u32 orig_seq  = bpf_ntohl(tcp->seq);
    __u32 orig_ack  = bpf_ntohl(tcp->ack_seq);

    tcp->source = orig_dst;
    tcp->dest   = orig_src;

    // Set RST+ACK if the original had ACK, else just RST
    if (tcp->ack) {
        tcp->seq    = tcp->ack_seq;  // echo their ack as our seq
        tcp->ack_seq = bpf_htonl(orig_seq + 1);
        tcp->rst    = 1;
        tcp->ack    = 1;
    } else {
        tcp->ack_seq = bpf_htonl(orig_seq + (tcp->syn ? 1 : 0));
        tcp->rst    = 1;
        tcp->ack    = 1;
    }

    // Clear other flags
    tcp->fin = 0; tcp->syn = 0; tcp->psh = 0; tcp->urg = 0;
    tcp->window = 0;
    tcp->urg_ptr = 0;

    // Trim to IP+TCP headers only
    __u16 new_ip_len = (ip->ihl * 4) + (tcp->doff * 4);
    ip->tot_len = bpf_htons(new_ip_len);

    // Recalc IP checksum
    ip->check = 0;
    ip->check = ip_csum(ip, ip->ihl * 2);

    // Recalc TCP checksum
    tcp->check = 0;
    __u32 tcplen = tcp->doff * 4;
    __u32 csum = tcp_pseudo_csum(ip->saddr, ip->daddr, tcplen);
    tcp->check = ip_csum(tcp, tcplen / 2);

    // Fixup: add pseudo-header to the folded result
    csum += (__u16)~(tcp->check);
    tcp->check = fold_csum(csum);

    // If no payload, set checksum directly
    if (tcp->doff == 5) {
        __u32 sum = tcp_pseudo_csum(ip->saddr, ip->daddr, (__u16)(new_ip_len - (ip->ihl * 4)));
        tcp->check = ip_csum(tcp, tcp->doff * 2);
        // Simplified: use 0 (many NICs offload TCP checksum anyway)
    }

    increment_stat(STAT_RST_SENT);
    return XDP_TX;
}

// ─── IP / IP+Port 阻斷檢查 ──────────────────────────────────────────────

// 檢查 IP 是否被完全封鎖 (bitmask 控制哪些協議)
static __always_inline int check_blocked_ip(__u32 ip_addr, __u8 proto,
                                             __u32 *ip_mode) {
    __u32 *blocked = bpf_map_lookup_elem(&blocked_ips, &ip_addr);
    if (!blocked) return 0;

    struct config *cfg = get_config();
    __u32 mode = cfg ? cfg->ip_mode : 7;

    switch (proto) {
    case IPPROTO_TCP:  return (mode & 1) != 0;
    case IPPROTO_UDP:  return (mode & 2) != 0;
    case IPPROTO_ICMP: return (mode & 4) != 0;
    default:           return 1;  // block unknown too
    }
}

// 檢查 IP:Port 是否被封鎖
static __always_inline int check_blocked_ip_port(__u32 ip_addr, __u16 port,
                                                  __u8 proto, __u32 *mask) {
    struct ip_port_key k = { .ip = ip_addr, .port = port, .proto = proto, .pad = 0 };
    __u32 *blocked = bpf_map_lookup_elem(&blocked_ip_ports, &k);
    if (!blocked) return 0;

    struct config *cfg = get_config();
    __u32 m = cfg ? cfg->ip_port_mask : 3;

    if (proto == IPPROTO_TCP) return (m & 1) != 0;
    if (proto == IPPROTO_UDP) return (m & 2) != 0;
    return 0;
}

// 提取目標地址和端口
static __always_inline void extract_dst(struct iphdr *ip,
                                         __u32 *dst_ip, __u16 *dst_port) {
    *dst_ip = ip->daddr;
}

// ─── IPv4 處理入口 ──────────────────────────────────────────────────────

static __always_inline int handle_ipv4(struct xdp_md *ctx, struct ethhdr *eth,
                                        struct iphdr *ip) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data     = (void *)(long)ctx->data;

    __u32 ip_hdr_len = ip->ihl * 4;
    __u32 src_ip = ip->saddr;
    __u32 dst_ip = ip->daddr;

    // === TCP ===
    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (void *)ip + ip_hdr_len;
        if ((void *)(tcp + 1) > data_end) return XDP_PASS;

        __u16 dport = bpf_ntohs(tcp->dest);
        __u16 sport = bpf_ntohs(tcp->source);
        __u32 off = sizeof(struct ethhdr) + ip_hdr_len + (tcp->doff * 4);

        // 1) IP:Port 檢查 (destination)
        if (check_blocked_ip_port(dst_ip, dport, IPPROTO_TCP, NULL)) {
            increment_stat(STAT_IP_PORT_BLOCKED);
            increment_stat(STAT_BLOCKED_PACKETS);
            return send_tcp_rst(ctx, eth, ip, tcp);
        }
        // Also check source IP:Port
        if (check_blocked_ip_port(src_ip, sport, IPPROTO_TCP, NULL)) {
            increment_stat(STAT_IP_PORT_BLOCKED);
            increment_stat(STAT_BLOCKED_PACKETS);
            return send_tcp_rst(ctx, eth, ip, tcp);
        }

        // 2) IP 檢查 (full block)
        if (check_blocked_ip(dst_ip, IPPROTO_TCP, NULL) ||
            check_blocked_ip(src_ip, IPPROTO_TCP, NULL)) {
            increment_stat(STAT_IP_BLOCKED);
            increment_stat(STAT_BLOCKED_PACKETS);
            return send_tcp_rst(ctx, eth, ip, tcp);
        }

        // 3) HTTP / TLS 域名檢查
        if (dport == 80)
            return check_http_host(data, data_end, off);
        if (dport == 443)
            return check_tls_sni(data, data_end, off);
    }
    // === UDP ===
    else if (ip->protocol == IPPROTO_UDP) {
        struct udphdr *udp = (void *)ip + ip_hdr_len;
        if ((void *)(udp + 1) > data_end) return XDP_PASS;

        __u16 dport = bpf_ntohs(udp->dest);
        __u16 sport = bpf_ntohs(udp->source);
        __u32 off = sizeof(struct ethhdr) + ip_hdr_len + sizeof(struct udphdr);

        // 1) IP:Port 檢查
        if (check_blocked_ip_port(dst_ip, dport, IPPROTO_UDP, NULL) ||
            check_blocked_ip_port(src_ip, sport, IPPROTO_UDP, NULL)) {
            increment_stat(STAT_IP_PORT_BLOCKED);
            increment_stat(STAT_BLOCKED_PACKETS);
            return XDP_DROP;
        }

        // 2) IP 檢查
        if (check_blocked_ip(dst_ip, IPPROTO_UDP, NULL) ||
            check_blocked_ip(src_ip, IPPROTO_UDP, NULL)) {
            increment_stat(STAT_IP_BLOCKED);
            increment_stat(STAT_BLOCKED_PACKETS);
            return XDP_DROP;
        }

        // 3) DNS
        if (dport == 53)
            return check_dns(ctx, data, data_end, off, eth, ip, udp);
    }
    // === ICMP ===
    else if (ip->protocol == IPPROTO_ICMP) {
        if (check_blocked_ip(dst_ip, IPPROTO_ICMP, NULL) ||
            check_blocked_ip(src_ip, IPPROTO_ICMP, NULL)) {
            increment_stat(STAT_BLOCKED_PACKETS);
            increment_stat(STAT_IP_BLOCKED);
            return XDP_DROP;
        }
    }

    return XDP_PASS;
}

// ─── IPv6 處理入口 (簡化版) ──────────────────────────────────────────────

static __always_inline int handle_ipv6(struct xdp_md *ctx, struct ethhdr *eth,
                                        struct ipv6hdr *ip6) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data     = (void *)(long)ctx->data;

    if (ip6->nexthdr == IPPROTO_TCP) {
        struct tcphdr *tcp = (void *)(ip6 + 1);
        if ((void *)(tcp + 1) > data_end) return XDP_PASS;

        __u16 dport = bpf_ntohs(tcp->dest);
        __u32 off = sizeof(struct ethhdr) + sizeof(struct ipv6hdr) + (tcp->doff * 4);

        if (dport == 80)
            return check_http_host(data, data_end, off);
        if (dport == 443)
            return check_tls_sni(data, data_end, off);
    }
    else if (ip6->nexthdr == IPPROTO_UDP) {
        struct udphdr *udp = (void *)(ip6 + 1);
        if ((void *)(udp + 1) > data_end) return XDP_PASS;

        if (bpf_ntohs(udp->dest) == 53) {
            __u32 off = sizeof(struct ethhdr) + sizeof(struct ipv6hdr) + sizeof(struct udphdr);
            return check_dns(ctx, data, data_end, off, eth, NULL, udp);
        }
    }
    return XDP_PASS;
}

// ─── XDP 主入口 ─────────────────────────────────────────────────────────

SEC("xdp")
int xdp_filter(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data     = (void *)(long)ctx->data;

    increment_stat(STAT_TOTAL_PACKETS);

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) return XDP_PASS;

    __u16 proto = bpf_ntohs(eth->h_proto);

    if (proto == ETH_P_IP) {
        struct iphdr *ip = (void *)(eth + 1);
        if ((void *)(ip + 1) > data_end) return XDP_PASS;
        return handle_ipv4(ctx, eth, ip);
    }

    if (proto == ETH_P_IPV6) {
        struct ipv6hdr *ip6 = (void *)(eth + 1);
        if ((void *)(ip6 + 1) > data_end) return XDP_PASS;
        return handle_ipv6(ctx, eth, ip6);
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
