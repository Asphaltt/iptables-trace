#include "iptables_trace.h"
#include "bpf_kprobe_args.h"
#include "maps.bpf.h"

/**
 * Common tracepoint handler. Detect IPv4/IPv6 and
 * emit event with address, interface and namespace.
 */
static __inline bool
do_trace_skb(struct event_t *event, struct pt_regs *ctx,
    struct sk_buff *skb)
{
    unsigned char *l3_header;
    u8 ip_version, l4_proto;

    event->flags |= SKBTRACER_EVENT_IF;
    set_event_info(skb, event);
    set_pkt_info(skb, &event->pkt_info);
    set_ether_info(skb, &event->l2_info);

    l3_header = get_l3_header(skb);
    ip_version = get_ip_version(l3_header);
    if (ip_version == 4) {
        event->l2_info.l3_proto = ETH_P_IP;
        set_ipv4_info(skb, &event->l3_info);
    } else if (ip_version == 6) {
        event->l2_info.l3_proto = ETH_P_IPV6;
        set_ipv6_info(skb, &event->l3_info);
    } else {
        return false;
    }

    l4_proto = event->l3_info.l4_proto;
    if (l4_proto == IPPROTO_TCP) {
        set_tcp_info(skb, &event->l4_info);
    } else if (l4_proto == IPPROTO_UDP) {
        set_udp_info(skb, &event->l4_info);
    } else if (l4_proto == IPPROTO_ICMP || l4_proto == IPPROTO_ICMPV6) {
        set_icmp_info(skb, &event->icmp_info);
    } else {
        return false;
    }

    return true;
}

static __noinline int
__ipt_do_table_in(struct pt_regs *ctx,
    struct sk_buff *skb,
    const struct nf_hook_state *state,
    struct xt_table *table)
{
    u64 pid_tgid;
    pid_tgid = bpf_get_current_pid_tgid();

    if (filter_pid(pid_tgid >> 32) || filter_netns(skb) || filter_l3_and_l4_info(skb))
        return false;

    struct ipt_do_table_args args = {
        .skb = skb,
        .state = state,
        .table = table,
    };

    args.start_ns = bpf_ktime_get_ns();
    bpf_map_update_elem(&skbtracer_ipt, &pid_tgid, &args, BPF_ANY);

    return BPF_OK;
};

static __inline int
__ipt_do_table_trace(struct pt_regs *ctx,
    u8 pf,
    unsigned int hooknum,
    struct sk_buff *skb,
    struct net_device *in,
    struct net_device *out,
    char *tablename,
    char *chainname,
    unsigned int rulenum)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();
    void *val = bpf_map_lookup_elem(&skbtracer_ipt, &pid_tgid);
    if (!val)
        return BPF_OK;

    struct event_t *event = GET_EVENT_BUF();
    if (!event)
        return BPF_OK;

    __builtin_memset(event, 0, sizeof(*event));

    if (!do_trace_skb(event, ctx, skb))
        return BPF_OK;

    event->flags |= SKBTRACER_EVENT_IPTABLES_TRACE;

    struct iptables_trace_t *trace = &event->trace_info;

    read_dev_name((char *)&trace->in, in);
    read_dev_name((char *)&trace->out, out);
    bpf_probe_read_kernel_str(&trace->tablename, XT_TABLE_MAXNAMELEN, tablename);
    bpf_probe_read_kernel_str(&trace->chainname, XT_TABLE_MAXNAMELEN, chainname);
    trace->rulenum = (u32)rulenum;
    trace->hooknum = (u32)hooknum;
    trace->pf = pf;

    bpf_perf_event_output(ctx, &skbtracer_event, BPF_F_CURRENT_CPU, event, sizeof(*event));

    return BPF_OK;
}

static __noinline int
__ipt_do_table_out(struct pt_regs *ctx, uint verdict)
{
    const struct nf_hook_state *state;
    struct ipt_do_table_args *args;
    struct xt_table *table;
    u64 ipt_delay;
    u64 pid_tgid;

    pid_tgid = bpf_get_current_pid_tgid();
    args = bpf_map_lookup_and_delete(&skbtracer_ipt, &pid_tgid);
    if (args == NULL)
        return BPF_OK;

    struct event_t *event = GET_EVENT_BUF();
    if (!event)
        return BPF_OK;

    __builtin_memset(event, 0, sizeof(*event));

    if (!do_trace_skb(event, ctx, args->skb))
        return BPF_OK;

    event->flags |= SKBTRACER_EVENT_IPTABLE;

    ipt_delay = bpf_ktime_get_ns() - args->start_ns;
    table = args->table;
    state = args->state;
    set_iptables_info(table, state, (u32)verdict, ipt_delay, &event->ipt_info);

    bpf_perf_event_output(ctx, &skbtracer_event, BPF_F_CURRENT_CPU, event,
        sizeof(struct event_t));

    return BPF_OK;
}

// >= 5.16

SEC("kprobe/ipt_do_table")
int BPF_KPROBE(k_ipt_do_table, struct xt_table *table, struct sk_buff *skb,
    const struct nf_hook_state *state)
{
    return __ipt_do_table_in(ctx, skb, state, table);
};

// < 5.16

SEC("kprobe/ipt_do_table")
int BPF_KPROBE(k_ipt_do_table_old, struct sk_buff *skb,
    const struct nf_hook_state *state, struct xt_table *table)
{
    return __ipt_do_table_in(ctx, skb, state, table);
}

SEC("kretprobe/ipt_do_table")
int BPF_KRETPROBE(kr_ipt_do_table, uint ret)
{
    return __ipt_do_table_out(ctx, ret);
}

// SEC("kprobe/ip6t_do_table")
// int BPF_KPROBE(k_ip6t_do_table, void *priv, struct sk_buff *skb,
//     const struct nf_hook_state *state)
// {
//     struct xt_table *table = (struct xt_table *)priv;
//     return __ipt_do_table_in(ctx, skb, state, table);
// };

// SEC("kretprobe/ip6t_do_table")
// int BPF_KRETPROBE(kr_ip6t_do_table, uint ret)
// {
//     return __ipt_do_table_out(ctx, ret);
// }

SEC("kprobe/nf_log_trace")
int BPF_KPROBE(k_nf_log_trace, struct net *net, u_int8_t pf, unsigned int hooknum,
    struct sk_buff *skb, struct net_device *in)
{
    struct net_device *out;
    char *tablename;
    char *chainname;
    unsigned int rulenum;

    out = (typeof(out))(void *)regs_get_nth_argument(ctx, 5);
    tablename = (typeof(tablename))(void *)regs_get_nth_argument(ctx, 8);
    chainname = (typeof(chainname))(void *)regs_get_nth_argument(ctx, 9);
    rulenum = (typeof(rulenum))regs_get_nth_argument(ctx, 11);

    return __ipt_do_table_trace(ctx, pf, hooknum, skb, in, out, tablename,
        chainname, rulenum);
}

SEC("kprobe/nft_do_chain")
int BPF_KPROBE(k_nft_do_chain, struct nft_pktinfo *pkt, void *priv)
{
    struct nft_chain *chain = (struct nft_chain *)priv;
    struct sk_buff *skb;
    u64 pid_tgid;

    pid_tgid = bpf_get_current_pid_tgid();
    bpf_probe_read_kernel(&skb, sizeof(skb), (void *) pkt);

    if (filter_pid(pid_tgid >> 32) || filter_netns(skb) || filter_l3_and_l4_info(skb))
        return false;

    struct ipt_do_table_args args = {
        .skb = skb,
        .chain = chain,
    };

    args.start_ns = bpf_ktime_get_ns();
    bpf_map_update_elem(&skbtracer_ipt, &pid_tgid, &args, BPF_ANY);

    return BPF_OK;
}

SEC("kretprobe/nft_do_chain")
int BPF_KRETPROBE(kr_nft_do_chain, uint verdict)
{
    struct ipt_do_table_args *args;
    struct nft_trace_t *trace;
    struct nft_table *table;
    struct nft_chain *chain;
    struct event_t *event;
    u64 ipt_delay;
    u64 pid_tgid;
    char *name;

    pid_tgid = bpf_get_current_pid_tgid();
    args = bpf_map_lookup_and_delete(&skbtracer_ipt, &pid_tgid);
    if (!args)
        return BPF_OK;

    event = GET_EVENT_BUF();
    if (!event)
        return BPF_OK;

    __builtin_memset(event, 0, sizeof(*event));

    if (!do_trace_skb(event, ctx, args->skb))
        return BPF_OK;

    event->flags |= SKBTRACER_EVENT_NFT_CHAIN;

    event->start_ns = args->start_ns;
    ipt_delay = bpf_ktime_get_ns() - args->start_ns;

    chain = args->chain;
    trace = &event->nft_info;
    // BPF_CORE_READ_INTO(&name, chain, table, name);
    bpf_probe_read_kernel(&table, sizeof(table),
                          (void *)chain + offsetof(struct nft_chain, table));
    bpf_probe_read_kernel(&name, sizeof(name),
                          (void *)table + offsetof(struct nft_table, name));
    bpf_probe_read_kernel_str(trace->tablename, XT_TABLE_MAXNAMELEN, name);
    // BPF_CORE_READ_INTO(&name, chain, name);
    bpf_probe_read_kernel(&name, sizeof(name),
                          (void *)chain + offsetof(struct nft_chain, name));
    bpf_probe_read_kernel_str(trace->chainname, XT_TABLE_MAXNAMELEN, name);
    trace->delay = ipt_delay;
    trace->verdict = verdict;

    bpf_perf_event_output(ctx, &skbtracer_event, BPF_F_CURRENT_CPU, event,
                          sizeof(struct event_t));

    return BPF_OK;
}
