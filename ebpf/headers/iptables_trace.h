#ifndef __SKBTRACER_H_
#define __SKBTRACER_H_

#include "vmlinux.h"
#include "bpf_core_read.h"
#include "bpf_endian.h"
#include "bpf_helpers.h"
#include "bpf_tracing.h"

#include "libiptables.h"

#include "icmp.h"
#include "if_ether.h"

char _license[] SEC("license") = "GPL";

#define IPPROTO_HOPOPTS 0 /* IPv6 hop-by-hop options      */
#define IPPROTO_ROUTING 43 /* IPv6 routing header          */
#define IPPROTO_FRAGMENT 44 /* IPv6 fragmentation header    */
#define IPPROTO_ICMPV6 58 /* ICMPv6                       */
#define IPPROTO_NONE 59 /* IPv6 no next header          */
#define IPPROTO_DSTOPTS 60 /* IPv6 destination options     */
#define IPPROTO_MH 135 /* IPv6 mobility header         */

#define ICMPV6_ECHO_REQUEST 128
#define ICMPV6_ECHO_REPLY 129
#define ICMPV6_MGM_QUERY 130
#define ICMPV6_MGM_REPORT 131
#define ICMPV6_MGM_REDUCTION 132

#define IFNAMSIZ 16
#define ADDRSIZE 16
#define MAC_HEADER_SIZE 14
#define FUNCNAME_MAX_LEN 32
#define XT_TABLE_MAXNAMELEN 32

#define NULL ((void *)0)
#define MAX_STACKDEPTH 50

struct config {
    u32 netns;
    u32 pid;
    u32 ip;
    u16 port;
    u16 icmpid;
    u8 proto;
    u8 pad[3];
} __attribute__((packed));

volatile const struct config CFG;
#define cfg (&CFG)

union addr {
    u32 v4addr;
    struct {
        u64 pre;
        u64 post;
    } v6addr;
    u64 pad[2];
} __attribute__((packed));

struct l2_info_t {
    u8 dest_mac[6];
    u16 l3_proto;
} __attribute__((packed));

struct l3_info_t {
    union addr saddr;
    union addr daddr;
    u16 tot_len;
    u8 ip_version;
    u8 l4_proto;
} __attribute__((packed));

struct l4_info_t {
    u16 sport;
    u16 dport;
    u16 tcpflags;
    u8 pad[2];
} __attribute__((packed));

struct icmp_info_t {
    u16 icmpid;
    u16 icmpseq;
    u8 icmptype;
    u8 pad[3];
} __attribute__((packed));

struct iptables_info_t {
    char tablename[XT_TABLE_MAXNAMELEN];
    u64 delay;
    u32 verdict;
    u8 hook;
    u8 pf;
    u8 pad[2];
} __attribute__((packed));

struct iptables_trace_t {
    char in[IFNAMSIZ];
    char out[IFNAMSIZ];
    char tablename[XT_TABLE_MAXNAMELEN];
    char chainname[XT_TABLE_MAXNAMELEN];
    u32 rulenum;
    u32 hooknum;
    u8 pf;
    u8 pad[3];
} __attribute__((packed));

struct nft_trace_t {
    char tablename[XT_TABLE_MAXNAMELEN];
    char chainname[XT_TABLE_MAXNAMELEN];
    u64 delay;
    u32 verdict;
} __attribute__((packed));

struct pkt_info_t {
    char ifname[IFNAMSIZ];
    u32 len;
    u32 cpu;
    u32 pid;
    u32 netns;
    u8 pkt_type; // skb->pkt_type
    u8 pad[3];
} __attribute__((packed));

struct event_t {
    u64 skb;
    u64 start_ns;
    u8 flags;
    u8 pad[3];

    struct pkt_info_t pkt_info;
    struct l2_info_t l2_info;
    struct l3_info_t l3_info;
    struct l4_info_t l4_info;
    struct icmp_info_t icmp_info;
    union {
        struct iptables_info_t ipt_info;
        struct iptables_trace_t trace_info;
        struct nft_trace_t nft_info;
    };
} __attribute__((packed));

#define __sizeof_event sizeof(struct event_t)
#define __sizeof_event_base 8+8+4+sizeof(struct pkt_info_t)+sizeof(struct l2_info_t)+sizeof(struct l3_info_t)+sizeof(struct l4_info_t)+sizeof(struct icmp_info_t)
#define __sizeof_ipt_info sizeof(struct iptables_info_t)
#define __sizeof_ipt_trace sizeof(struct iptables_trace_t)

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, u32);
    __type(value, struct event_t);
    __uint(max_entries, 1);
} event_buf SEC(".maps");

static __always_inline struct event_t *
get_event_buf(void)
{
    u32 ev_buff_id = 0;
    struct event_t *ev;
    ev = bpf_map_lookup_elem(&event_buf, &ev_buff_id);
    if (!ev)
        return NULL;

    __builtin_memset(ev, 0, sizeof(*ev));
    return ev;
}

#define GET_EVENT_BUF() get_event_buf()

#define SKBTRACER_EVENT_IF 0x01
#define SKBTRACER_EVENT_IPTABLE 0x02
#define SKBTRACER_EVENT_IPTABLES_TRACE 0x04
#define SKBTRACER_EVENT_NFT_CHAIN 0x08

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(max_entries, 1024);
} skbtracer_event SEC(".maps");

struct ipt_do_table_args {
    struct sk_buff *skb;
    const struct nf_hook_state *state;
    struct xt_table *table;
    struct nft_chain *chain;
    u64 start_ns;
} __attribute__((packed)) /* __attribute__((preserve_access_index)) */;

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, u64);
    __type(value, struct ipt_do_table_args);
    __uint(max_entries, 1024);
} skbtracer_ipt SEC(".maps");

static __always_inline u32
get_netns(struct sk_buff *skb)
{
    u32 netns;

    // Get netns inode. The code below is equivalent to: netns =
    // skb->dev->nd_net.net->ns.inum
    netns = BPF_CORE_READ(skb, dev, nd_net.net, ns.inum);

    // maybe the skb->dev is not init, get it by
    // skb->sk->__sk_common.skc_net.net->ns.inum.
    if (netns == 0)
        netns = BPF_CORE_READ(skb, sk, __sk_common.skc_net.net, ns.inum);

    return netns;
}

union ___skb_pkt_type {
    u8 value;
    struct {
        u8 __pkt_type_offset[0];
        u8 pkt_type : 3;
        u8 pfmemalloc : 1;
        u8 ignore_df : 1;

        u8 nf_trace : 1;
        u8 ip_summed : 2;
    };
};

static __always_inline u8
get_pkt_type(struct sk_buff *skb)
{
    union ___skb_pkt_type type = {};
    bpf_probe_read(&type.value, 1, &skb->__pkt_type_offset);
    return type.pkt_type;
    // return BPF_CORE_READ_BITFIELD(skb, pkt_type); // Failed
}

static __always_inline u8
get_ip_version(void *hdr)
{
    u8 first_byte;
    bpf_probe_read(&first_byte, 1, hdr);
    return (first_byte >> 4) & 0x0f;
}

static __always_inline u8
get_ipv4_header_len(void *hdr)
{
    u8 first_byte;
    bpf_probe_read(&first_byte, 1, hdr);
    return (first_byte & 0x0f) * 4;
}

static __always_inline unsigned char *
get_l2_header(struct sk_buff *skb)
{
    unsigned char *head = BPF_CORE_READ(skb, head);
    u16 mac_header = BPF_CORE_READ(skb, mac_header);
    return head + mac_header;
}

static __always_inline unsigned char *
get_l3_header(struct sk_buff *skb)
{
    unsigned char *head = BPF_CORE_READ(skb, head);
    u16 mac_header = BPF_CORE_READ(skb, mac_header);
    u16 network_header = BPF_CORE_READ(skb, network_header);
    if (network_header == 0)
        network_header = mac_header + MAC_HEADER_SIZE;
    return head + network_header;
}

static __always_inline unsigned char *
get_l4_header(struct sk_buff *skb)
{
    u16 transport_size = 0;
    unsigned char *l3_header = get_l3_header(skb);
    u8 ip_version = get_ip_version(l3_header);
    if (ip_version == 6)
        transport_size = sizeof(struct ipv6hdr);
    else
        transport_size = get_ipv4_header_len(l3_header);
    return l3_header + transport_size;
}

static __always_inline void
set_event_info(struct sk_buff *skb, struct event_t *ev)
{
    ev->skb = (u64)skb;
    ev->start_ns = bpf_ktime_get_ns();
}

static __always_inline void
read_dev_name(char *dst, const struct net_device *dev)
{
    dst[0] = 0;
    if (dev)
        bpf_probe_read_kernel_str(dst, IFNAMSIZ, &dev->name);
}

static __always_inline void
set_pkt_info(struct sk_buff *skb, struct pkt_info_t *pkt_info)
{
    struct net_device *dev = BPF_CORE_READ(skb, dev);
    pkt_info->len = BPF_CORE_READ(skb, len);
    pkt_info->cpu = bpf_get_smp_processor_id();
    pkt_info->pid = bpf_get_current_pid_tgid() >> 32;
    pkt_info->netns = get_netns(skb);
    pkt_info->pkt_type = get_pkt_type(skb);

    read_dev_name((char *)&pkt_info->ifname, dev);
}

static __always_inline void
set_ether_info(struct sk_buff *skb, struct l2_info_t *l2_info)
{
    unsigned char *l2_header = get_l2_header(skb);
    bpf_probe_read(&l2_info->dest_mac, 6, l2_header);
}

static __always_inline void
set_ipv4_info(struct sk_buff *skb, struct l3_info_t *l3_info)
{
    struct iphdr *iph = (struct iphdr *)get_l3_header(skb);
    l3_info->saddr.v4addr = BPF_CORE_READ(iph, saddr);
    l3_info->daddr.v4addr = BPF_CORE_READ(iph, daddr);
    l3_info->tot_len = bpf_ntohs(BPF_CORE_READ(iph, tot_len));
    l3_info->l4_proto = BPF_CORE_READ(iph, protocol);
    l3_info->ip_version = get_ip_version(iph);
}

static __always_inline void
set_ipv6_info(struct sk_buff *skb, struct l3_info_t *l3_info)
{
    struct ipv6hdr *iph = (struct ipv6hdr *)get_l3_header(skb);
    bpf_probe_read(&l3_info->saddr.v6addr, ADDRSIZE, &iph->saddr);
    bpf_probe_read(&l3_info->daddr.v6addr, ADDRSIZE, &iph->daddr);
    l3_info->tot_len = bpf_ntohs(BPF_CORE_READ(iph, payload_len));
    l3_info->l4_proto = BPF_CORE_READ(iph, nexthdr);
    l3_info->ip_version = get_ip_version(iph);
}

static __always_inline void
set_tcp_info(struct sk_buff *skb, struct l4_info_t *l4_info)
{
    struct tcphdr *tcph = (struct tcphdr *)get_l4_header(skb);
    l4_info->sport = bpf_ntohs(BPF_CORE_READ(tcph, source));
    l4_info->dport = bpf_ntohs(BPF_CORE_READ(tcph, dest));
    bpf_probe_read(&l4_info->tcpflags, 2, (char *)tcph + 12);
}

static __always_inline void
set_udp_info(struct sk_buff *skb, struct l4_info_t *l4_info)
{
    struct udphdr *uh = (struct udphdr *)get_l4_header(skb);
    l4_info->sport = bpf_ntohs(BPF_CORE_READ(uh, source));
    l4_info->dport = bpf_ntohs(BPF_CORE_READ(uh, dest));
}

static __always_inline void
set_icmp_info(struct sk_buff *skb, struct icmp_info_t *icmp_info)
{
    struct icmphdr ih;
    unsigned char *l4_header = get_l4_header(skb);
    bpf_probe_read(&ih, sizeof(ih), l4_header);

    icmp_info->icmptype = ih.type;
    icmp_info->icmpid = bpf_ntohs(ih.un.echo.id);
    icmp_info->icmpseq = bpf_ntohs(ih.un.echo.sequence);
}

static __always_inline void
set_iptables_info(struct xt_table *table, const struct nf_hook_state *state,
                  u32 verdict, u64 delay, struct iptables_info_t *ipt_info)
{
    // BPF_CORE_READ_STR_INTO(&ipt_info->tablename, table, name); /* failed of bad CO-RE relocation */
    bpf_probe_read_kernel_str(&ipt_info->tablename, XT_TABLE_MAXNAMELEN,
                              (void *)table + offsetof(struct xt_table, name));
    BPF_CORE_READ_INTO(&ipt_info->hook, state, hook);
    BPF_CORE_READ_INTO(&ipt_info->pf, state, pf);
    ipt_info->delay = delay;
    ipt_info->verdict = verdict;
}

static __always_inline bool
filter_l3_and_l4_info(struct sk_buff *skb)
{
    u32 addr = cfg->ip;
    u8 proto = cfg->proto;
    u16 port = cfg->port;

    unsigned char *l3_header;
    unsigned char *l4_header;

    u8 ip_version;

    struct iphdr *iph;
    struct ipv6hdr *ip6h;
    u32 saddr, daddr;
    u8 l4_proto = 0;

    struct tcphdr *th;
    struct udphdr *uh;
    u16 sport, dport;

    struct icmphdr ih;
    u8 proto_icmp_echo_request;
    u8 proto_icmp_echo_reply;

    // filter ip addr
    l3_header = get_l3_header(skb);
    ip_version = get_ip_version(l3_header);
    if (ip_version == 4) {
        iph = (struct iphdr *)l3_header;
        if (addr) {
            saddr = BPF_CORE_READ(iph, saddr);
            daddr = BPF_CORE_READ(iph, daddr);
            return addr != saddr && addr != daddr;
        }

        // l4_proto = BPF_CORE_READ(iph, protocol);
        bpf_probe_read(&l4_proto, 1, &iph->protocol);
        if (l4_proto == IPPROTO_ICMP) {
            proto_icmp_echo_request = ICMP_ECHO;
            proto_icmp_echo_reply = ICMP_ECHOREPLY;
        }
    } else if (ip_version == 6) {
        ip6h = (struct ipv6hdr *)l3_header;
        // l4_proto = BPF_CORE_READ(ip6h, nexthdr);
        bpf_probe_read(&l4_proto, 1, &ip6h->nexthdr);
        if (l4_proto == IPPROTO_ICMPV6) {
            proto_icmp_echo_request = ICMPV6_ECHO_REQUEST;
            proto_icmp_echo_reply = ICMPV6_ECHO_REPLY;
        }
    } else {
        return true;
    }

    // filter layer 4 protocol
    if (proto && proto != l4_proto)
        return true;

    if (l4_proto == IPPROTO_ICMP || l4_proto == IPPROTO_ICMPV6) {
        l4_header = get_l4_header(skb);
        bpf_probe_read(&ih, sizeof(ih), l4_header);
        if (ih.type != proto_icmp_echo_request && ih.type != proto_icmp_echo_reply)
            return true;
        if (cfg->proto && cfg->proto != IPPROTO_ICMP && cfg->proto != IPPROTO_ICMPV6)
            return true;
        if (cfg->icmpid && cfg->icmpid != ih.un.echo.id)
            return true;
    } else if (l4_proto == IPPROTO_TCP || l4_proto == IPPROTO_UDP) {
        l4_header = get_l4_header(skb);
    } else {
        return true;
    }

    // filter layer 4 port
    if (port) {
        if (l4_proto == IPPROTO_TCP) {
            th = (struct tcphdr *)l4_header;
            sport = BPF_CORE_READ(th, source);
            dport = BPF_CORE_READ(th, dest);
            return port != sport && port != dport;
        } else if (l4_proto == IPPROTO_UDP) {
            uh = (struct udphdr *)l4_header;
            sport = BPF_CORE_READ(uh, source);
            dport = BPF_CORE_READ(uh, dest);
            return port != sport && port != dport;
        }
    }

    return false;
}

static __always_inline bool
filter_netns(struct sk_buff *skb)
{
    u32 netns = get_netns(skb);
    return cfg->netns && netns && cfg->netns != netns;
}

static __always_inline bool
filter_pid(u32 pid)
{
    return cfg->pid && cfg->pid != pid;
}

#endif // __SKBTRACER_H_