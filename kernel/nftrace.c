#include <linux/init.h> /* included for __init and __exit macros */
#include <linux/kernel.h> /* included for KERN_INFO */
#include <linux/module.h> /* included for all kernel modules */
#include <linux/skbuff.h> /* struct sk_buff */
#include <linux/bpf.h> /* bpf_prog_get_type_path */
#include <linux/filter.h> /* bpf_prog_run */
#include <linux/kprobes.h> /* for bpf kprobe/kretprobe */
#include <linux/jmp_label.h> /* for static_key operations */
#include <net/netfilter/nf_tables.h> /* for nf_tables */

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Leon Hwang <leonhwang@linux.dev>");
MODULE_DESCRnftION("A module for nftrace");

/* Unable to get bpf prog by FD or ID. */

static char *bpf_prog_entry_path = "",
            *bpf_prog_exit_path = "",
            *bpf_prog_trace_path = "";
module_param(bpf_prog_entry_path, charp, 0);
module_param(bpf_prog_exit_path, charp, 0);
module_param(bpf_prog_trace_path, charp, 0);

static int is_new_func = 0;
module_param(is_new_func, int, 0);

extern struct static_key_false nft_trace_enabled;
static bool original_nft_trace_enabled = false;

#define MAX_SYMBOL_LEN 32
static char symbol_nft_do_chain[MAX_SYMBOL_LEN] = "nft_do_chain";
static char symbol_nft_trace_packet[MAX_SYMBOL_LEN] = "__nft_trace_packet";

static struct kprobe kp_nft_do_chain = {
    .symbol_name = symbol_nft_do_chain,
    .flags = KPROBE_FLAG_FTRACE,
};
static struct kretprobe krp_nft_do_chain = {
    .kp = {
        .symbol_name = symbol_nft_do_chain,
        .flags = KPROBE_FLAG_FTRACE,
    },
};
static struct kprobe kp_nft_trace_packet = {
    .symbol_name = symbol_nft_trace_packet,
    .flags = KPROBE_FLAG_FTRACE,
};

static struct bpf_prog *__nft_bpf_prog_entry __read_mostly = NULL,
                       *__nft_bpf_prog_exit __read_mostly = NULL,
                       *__nft_bpf_prog_trace __read_mostly = NULL;

static int __bpf_check_path(struct bpf_prog **prog, char *path)
{
    *prog = bpf_prog_get_type_path(path, BPF_PROG_TYPE_KPROBE);
    return PTR_ERR_OR_ZERO(*prog);
}

#ifdef BPF_PROG_RUN
#define bpf_prog_run(prog, ctx) BPF_PROG_RUN(prog, ctx)
#endif

static bool __run_bpf_prog_entry(struct pt_regs *regs)
{
    return !!bpf_prog_run(__nft_bpf_prog_entry, regs);
}

static bool __run_bpf_prog_exit(struct pt_regs *regs)
{
    return !!bpf_prog_run(__nft_bpf_prog_exit, regs);
}

static bool __run_bpf_prog_trace(struct pt_regs *regs)
{
    return !!bpf_prog_run(__nft_bpf_prog_trace, regs);
}

static int __kprobe_prehandler_entry(struct kprobe *p, struct pt_regs *regs)
{
    __run_bpf_prog_entry(regs);
    return 0;
}

static int __kretprobe_handler_exit(struct kretprobe_instance *inst, struct pt_regs *regs)
{
    __run_bpf_prog_exit(regs);
    return 0;
}

static int __kprobe_prehandler_trace(struct kprobe *p, struct pt_regs *regs)
{
    struct nft_traceinfo *info;

    info = is_new_func ? regs->cx/* 4th arg */ : regs->di/* 1st arg */;
    info->trace = true;
    info->nf_trace = true;

    __run_bpf_prog_trace(regs);

    /* Hijack to disallow running nft_trace_notify(). */
    info->trace = false;
    info->nf_trace = false;

    return 0;
}

static int __init nft_trace_init(void)
{
    int ret;

    pr_info("[Y] entry_path=%s exit_path=%s trace_path=%s is_new_func=%d\n",
            bpf_prog_entry_path, bpf_prog_exit_path, bpf_prog_trace_path, is_new_func);

    if (unlikely(ret = __bpf_check_path(&__nft_bpf_prog_entry, bpf_prog_entry_path))) {
        pr_err("[X] nftrace, failed to get entry bpf prog, returned=%d\n", ret);
        return ret;
    }

    if (unlikely(ret = __bpf_check_path(&__nft_bpf_prog_exit, bpf_prog_exit_path))) {
        pr_err("[X] nftrace, failed to get exit bpf prog, returned=%d\n", ret);
        bpf_prog_put(__nft_bpf_prog_entry);
        return ret;
    }

    if (unlikely(ret = __bpf_check_path(&__nft_bpf_prog_trace, bpf_prog_trace_path))) {
        pr_err("[X] nftrace, failed to get trace bpf prog, returned=%d\n", ret);
        bpf_prog_put(__nft_bpf_prog_entry);
        bpf_prog_put(__nft_bpf_prog_exit);
        return ret;
    }

    kp_nft_do_chain.pre_handler = __kprobe_prehandler_entry;
    krp_nft_do_chain.handler = __kretprobe_handler_exit;
    kp_nft_trace_packet.pre_handler = __kprobe_prehandler_trace;

    ret = register_kretprobe(&krp_nft_do_chain);
    if (unlikely(ret < 0)) {
        pr_err("[X] nftrace, failed to register krp_nft_do_chain, returned=%d\n", ret);
        goto L_put_bpf_progs;
    }

    ret = register_kprobe(&kp_nft_do_chain);
    if (unlikely(ret < 0)) {
        pr_err("[X] nftrace, failed to register kp_nft_do_chain, returned=%d\n", ret);
        goto L_unregister_kretprobes;
    }


    ret = register_kprobe(&kp_nft_trace_packet);
    if (unlikely(ret < 0)) {
        pr_err("[X] nftrace, failed to register kp_nft_trace_packet, returned=%d\n", ret);
        unregister_kprobe(&kp_nft_do_chain);
        goto L_unregister_kretprobes;
    }

    original_nft_trace_enabled = static_key_true(&nft_trace_enabled);
    static_key_enable(&nft_trace_enabled);

    pr_info("[+] nftrace inited!\n");

    return 0;

L_unregister_kretprobes:
    unregister_kretprobe(&krp_nft_do_chain);

L_put_bpf_progs:
    bpf_prog_put(__nft_bpf_prog_entry);
    bpf_prog_put(__nft_bpf_prog_exit);
    bpf_prog_put(__nft_bpf_prog_trace);

    return ret;
}

static void __exit nft_trace_exit(void)
{
    if (!original_nft_trace_enabled)
        static_key_disable(&nft_trace_enabled);

    unregister_kprobe(&kp_nft_do_chain);
    unregister_kprobe(&kp_nft_trace_packet);
    unregister_kretprobe(&krp_nft_do_chain);

    bpf_prog_put(__nft_bpf_prog_entry);
    bpf_prog_put(__nft_bpf_prog_exit);
    bpf_prog_put(__nft_bpf_prog_trace);

    pr_info("[-] nftrace exited!\n");
}

module_init(nft_trace_init);
module_exit(nft_trace_exit);
