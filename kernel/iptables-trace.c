#include <linux/init.h> // included for __init and __exit macros
#include <linux/kernel.h> // included for KERN_INFO
#include <linux/module.h> // included for all kernel modules
#include <linux/skbuff.h> // struct sk_buff
#include <linux/bpf.h> // bpf_prog_get_type_dev bpf_prog_get_type_path
#include <linux/filter.h> // bpf_prog_run
#include <linux/kprobes.h> // for bpf kprobe/kretprobe

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Leon Hwang <le0nhwan9@gmail.com>");
MODULE_DESCRIPTION("A Module for iptables-trace");

// static u32 bpf_prog_entry_fd = 0,
//            bpf_prog_exit_fd = 0,
//            bpf_prog_trace_fd = 0;
// module_param(bpf_prog_entry_fd, int, 0);
// module_param(bpf_prog_exit_fd, int, 0);
// module_param(bpf_prog_trace_fd, int, 0);

static char *bpf_prog_entry_path = "",
            *bpf_prog_exit_path = "",
            *bpf_prog_trace_path = "";
module_param(bpf_prog_entry_path, charp, 0);
module_param(bpf_prog_exit_path, charp, 0);
module_param(bpf_prog_trace_path, charp, 0);

static int version_gte_5_16 = 0;
module_param(version_gte_5_16, int, 0);

#define MAX_SYMBOL_LEN 64
static char symbol_ipt_do_table[MAX_SYMBOL_LEN] = "ipt_do_table";
static char symbol_ip6t_do_table[MAX_SYMBOL_LEN] = "ip6t_do_table";
static char symbol_nf_log_trace[MAX_SYMBOL_LEN] = "nf_log_trace";

static struct kprobe kp_ipt_do_tables = {
    .symbol_name = symbol_ipt_do_table,
    .flags = KPROBE_FLAG_FTRACE,
};
static struct kretprobe krp_ipt_do_tables = {
    .kp = {
        .symbol_name = symbol_ipt_do_table,
        .flags = KPROBE_FLAG_FTRACE,
    },
};
static struct kprobe kp_ip6t_do_tables = {
    .symbol_name = symbol_ip6t_do_table,
    .flags = KPROBE_FLAG_FTRACE,
};
static struct kretprobe krp_ip6t_do_tables = {
    .kp = {
        .symbol_name = symbol_ip6t_do_table,
        .flags = KPROBE_FLAG_FTRACE,
    },
};
static struct kprobe kp_nf_log_trace = {
    .symbol_name = symbol_nf_log_trace,
    .flags = KPROBE_FLAG_FTRACE,
};

static struct bpf_prog *__ipt_bpf_prog_entry __read_mostly = NULL,
                       *__ipt_bpf_prog_exit __read_mostly = NULL,
                       *__ipt_bpf_prog_trace __read_mostly = NULL;

// static int __bpf_check_ufd(struct bpf_prog **prog, u32 ufd)
// {
//     *prog = bpf_prog_get_type_dev(ufd, BPF_PROG_TYPE_KPROBE, false);
//     return PTR_ERR_OR_ZERO(*prog);
// }

static int __bpf_check_path(struct bpf_prog **prog, char *path)
{
    *prog = bpf_prog_get_type_path(path, BPF_PROG_TYPE_KPROBE);
    return PTR_ERR_OR_ZERO(*prog);
}

static bool __run_bpf_prog_entry(struct pt_regs *regs)
{
    return !!bpf_prog_run(__ipt_bpf_prog_entry, regs);
}

static bool __run_bpf_prog_exit(struct pt_regs *regs)
{
    return !!bpf_prog_run(__ipt_bpf_prog_exit, regs);
}

static bool __run_bpf_prog_trace(struct pt_regs *regs)
{
    return !!bpf_prog_run(__ipt_bpf_prog_trace, regs);
}

static int __kprobe_prehandler_entry(struct kprobe *p, struct pt_regs *regs)
{
    struct sk_buff *skb;

    __run_bpf_prog_entry(regs);

    // offsetof(struct pt_regs, di),
    // offsetof(struct pt_regs, si),
    // offsetof(struct pt_regs, dx),
    // offsetof(struct pt_regs, cx),
    // offsetof(struct pt_regs, r8),
    // offsetof(struct pt_regs, r9),

    skb = version_gte_5_16 ? (typeof(skb))regs->si : (typeof(skb))regs->di;
    skb->nf_trace = 1; // Note: force to enable nf TRACE

    // pr_info("[iptables-trace] entry\n");

    return 0;
}

static int __kretprobe_handler_exit(struct kretprobe_instance *inst, struct pt_regs *regs)
{
    __run_bpf_prog_exit(regs);

    return 0;
}

static int __kprobe_prehandler_trace(struct kprobe *p, struct pt_regs *regs)
{
    __run_bpf_prog_trace(regs);

    regs->si = 0; // Note: hijack and do not run the nf_log_trace()

    // pr_info("[iptables-trace] trace\n");

    return 0;
}

static int __init ipt_trace_init(void)
{
    int ret;

    pr_info("[Y] entry_path=%s exit_path=%s trace_path=%s version_gte_5_16=%d\n",
        bpf_prog_entry_path, bpf_prog_exit_path, bpf_prog_trace_path, version_gte_5_16);
    // pr_info("[Y] entry_fd=%d exit_fd=%d trace_fd=%d version_gte_5_16=%d\n",
    //     bpf_prog_entry_fd, bpf_prog_exit_fd, bpf_prog_trace_fd, version_gte_5_16);

    // if (0 != (ret = __bpf_check_ufd(&__ipt_bpf_prog_entry, bpf_prog_entry_fd))) {
    //     pr_err("[X] iptables-trace, failed to get entry bpf prog, returned=%d\n", ret);
    //     return ret;
    // }

    // if (0 != (ret = __bpf_check_ufd(&__ipt_bpf_prog_exit, bpf_prog_exit_fd))) {
    //     pr_err("[X] iptables-trace, failed to get exit bpf prog, returned=%d\n", ret);
    //     bpf_prog_put(__ipt_bpf_prog_entry);
    //     return ret;
    // }

    // if (0 != (ret = __bpf_check_ufd(&__ipt_bpf_prog_trace, bpf_prog_trace_fd))) {
    //     pr_err("[X] iptables-trace, failed to get trace bpf prog, returned=%d\n", ret);
    //     bpf_prog_put(__ipt_bpf_prog_entry);
    //     bpf_prog_put(__ipt_bpf_prog_exit);
    //     return ret;
    // }

    if (unlikely(0 != (ret = __bpf_check_path(&__ipt_bpf_prog_entry, bpf_prog_entry_path)))) {
        pr_err("[X] iptables-trace, failed to get entry bpf prog, returned=%d\n", ret);
        return ret;
    }

    if (unlikely(0 != (ret = __bpf_check_path(&__ipt_bpf_prog_exit, bpf_prog_exit_path)))) {
        pr_err("[X] iptables-trace, failed to get exit bpf prog, returned=%d\n", ret);
        bpf_prog_put(__ipt_bpf_prog_entry);
        return ret;
    }

    if (unlikely(0 != (ret = __bpf_check_path(&__ipt_bpf_prog_trace, bpf_prog_trace_path)))) {
        pr_err("[X] iptables-trace, failed to get trace bpf prog, returned=%d\n", ret);
        bpf_prog_put(__ipt_bpf_prog_entry);
        bpf_prog_put(__ipt_bpf_prog_exit);
        return ret;
    }

    kp_ipt_do_tables.pre_handler = __kprobe_prehandler_entry;
    kp_ip6t_do_tables.pre_handler = __kprobe_prehandler_entry;
    kp_nf_log_trace.pre_handler = __kprobe_prehandler_trace;

    krp_ipt_do_tables.handler = __kretprobe_handler_exit;
    krp_ip6t_do_tables.handler = __kretprobe_handler_exit;

    ret = register_kretprobe(&krp_ipt_do_tables);
    if (unlikely(ret < 0)) {
        pr_err("[X] iptables-trace, failed to register krp_ipt_do_tables, returned=%d\n", ret);
        goto L_put_bpf_progs;
    }

    ret = register_kretprobe(&krp_ip6t_do_tables);
    if (unlikely(ret < 0)) {
        unregister_kretprobe(&krp_ipt_do_tables);
        pr_err("[X] iptables-trace, failed to register krp_ip6t_do_tables, returned=%d\n", ret);
        goto L_put_bpf_progs;
    }

    ret = register_kprobe(&kp_ipt_do_tables);
    if (unlikely(ret < 0)) {
        pr_err("[X] iptables-trace, failed to register kp_ipt_do_tables, returned=%d\n", ret);
        goto L_unregister_kretprobes;
    }

    ret = register_kprobe(&kp_ip6t_do_tables);
    if (unlikely(ret < 0)) {
        pr_err("[X] iptables-trace, failed to register kp_ip6t_do_tables, returned=%d\n", ret);
        unregister_kprobe(&kp_ipt_do_tables);
        goto L_unregister_kretprobes;
    }

    ret = register_kprobe(&kp_nf_log_trace);
    if (unlikely(ret < 0)) {
        pr_err("[X] iptables-trace, failed to register kp_nf_log_trace, returned=%d\n", ret);
        unregister_kprobe(&kp_ipt_do_tables);
        unregister_kprobe(&kp_ip6t_do_tables);
        goto L_unregister_kretprobes;
    }

    pr_info("[+] iptables-trace inited!\n");

    return 0;

L_unregister_kretprobes:
    unregister_kretprobe(&krp_ipt_do_tables);
    unregister_kretprobe(&krp_ip6t_do_tables);

L_put_bpf_progs:
    bpf_prog_put(__ipt_bpf_prog_entry);
    bpf_prog_put(__ipt_bpf_prog_exit);
    bpf_prog_put(__ipt_bpf_prog_trace);

    return ret;
}

static void __exit ipt_trace_exit(void)
{
    unregister_kprobe(&kp_ipt_do_tables);
    unregister_kprobe(&kp_ip6t_do_tables);
    unregister_kprobe(&kp_nf_log_trace);
    unregister_kretprobe(&krp_ipt_do_tables);
    unregister_kretprobe(&krp_ip6t_do_tables);

    bpf_prog_put(__ipt_bpf_prog_entry);
    bpf_prog_put(__ipt_bpf_prog_exit);
    bpf_prog_put(__ipt_bpf_prog_trace);

    pr_info("[-] iptables-trace exited!\n");
}

module_init(ipt_trace_init);
module_exit(ipt_trace_exit);
