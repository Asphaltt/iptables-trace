#ifndef __BPF_KPROBE_ARGS_H_
#define __BPF_KPROBE_ARGS_H_

#include "vmlinux.h"

#include "bpf_tracing.h"

#define NR_REG_ARGUMENTS 6
#define NR_ARM64_MAX_REG_ARGUMENTS 31

static __inline unsigned long
regs_get_kernel_stack_nth_addr(struct pt_regs *regs, unsigned int n)
{
    unsigned long *addr = (unsigned long *)regs->sp, retval = 0;

    addr += n;
    return 0 != bpf_probe_read_kernel(&retval, sizeof(retval), addr) ? 0 : retval;
}

static __inline unsigned long
regs_get_nth_argument(struct pt_regs *regs,
    unsigned int n)
{
    switch (n) {
    case 0:
        return PT_REGS_PARM1_CORE(regs);
    case 1:
        return PT_REGS_PARM2_CORE(regs);
    case 2:
        return PT_REGS_PARM3_CORE(regs);
    case 3:
        return PT_REGS_PARM4_CORE(regs);
    case 4:
        return PT_REGS_PARM5_CORE(regs);
    case 5:
        return PT_REGS_PARM6_CORE(regs);
    default:
#ifdef __TARGET_ARCH_arm64
        if (n < NR_ARM64_MAX_REG_ARGUMENTS)
            return regs->regs[n];
        else
            return 0;
#elifdef __TARGET_ARCH_x86
        n -= NR_REG_ARGUMENTS - 1;
        return regs_get_kernel_stack_nth_addr(regs, n);
#else
        return 0;
#endif
    }
}

#endif // __BPF_KPROBE_ARGS_H_