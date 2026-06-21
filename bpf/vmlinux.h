/* Minimal vmlinux.h for XDP port filtering
 * Contains only essential structures for Ethernet/IP/TCP/UDP parsing
 */

#ifndef __VMLINUX_H__
#define __VMLINUX_H__

typedef unsigned char __u8;
typedef unsigned short __u16;
typedef unsigned int __u32;
typedef unsigned long long __u64;

typedef signed char __s8;
typedef signed short __s16;
typedef signed int __s32;
typedef signed long long __s64;

/* Ethernet header */
struct ethhdr {
    unsigned char   h_dest[6];
    unsigned char   h_source[6];
    __u16           h_proto;
} __attribute__((packed));

/* IP protocols */
#define IPPROTO_TCP     6
#define IPPROTO_UDP     17

/* IPv4 header */
struct iphdr {
    __u8    ihl:4,
            version:4;
    __u8    tos;
    __u16   tot_len;
    __u16   id;
    __u16   frag_off;
    __u8    ttl;
    __u8    protocol;
    __u16   check;
    __u32   saddr;
    __u32   daddr;
} __attribute__((packed));

/* TCP header */
struct tcphdr {
    __u16   source;
    __u16   dest;
    __u32   seq;
    __u32   ack_seq;
    __u16   res1:4,
            doff:4,
            fin:1,
            syn:1,
            rst:1,
            psh:1,
            ack:1,
            urg:1,
            ece:1,
            cwr:1;
    __u16   window;
    __u16   check;
    __u16   urg_ptr;
} __attribute__((packed));

/* UDP header */
struct udphdr {
    __u16   source;
    __u16   dest;
    __u16   len;
    __u16   check;
} __attribute__((packed));

/* XDP action codes */
enum xdp_action {
    XDP_ABORTED = 0,
    XDP_DROP,
    XDP_PASS,
    XDP_TX,
    XDP_REDIRECT,
};

/* XDP metadata */
struct xdp_md {
    __u32 data;
    __u32 data_end;
    __u32 data_meta;
    __u32 ingress_ifindex;
    __u32 rx_queue_index;
    __u32 egress_ifindex;
};

#endif /* __VMLINUX_H__ */
