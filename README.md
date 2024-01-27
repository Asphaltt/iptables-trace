# iptables-trace

`iptables-trace` is an eBPF enhanced [iptables TRACE](https://ipset.netfilter.org/iptables-extensions.man.html#lbDX)-alternative iptables TRACE.

## Kernel

It requires 5.2+ kernel to run eBPF CO-RE.

Meanwhile, `grep CONFIG_NETFILTER_XT_TARGET_TRACE /boot/config-$(uname -r)`
should be `y` to run kernel module.

## Kernel module and kprobes and bpf progs

It's because eBPF is unable to modify `skb->nf_trace` and `struct pt_regs`. But kernel module has the ability.

In hence, it's to modify `skb->nf_trace` and `struct pt_regs` in kernel module, then run bpf progs in kernel module.

1. Run the `kprobe` bpf prog on `ipt_do_table`/`ip6t_do_table`.
2. `skb->nf_trace = 1;` to run `nf_log_trace` function later.
3. Run the `kprobe` bpf prog on `nf_log_trace`.
4. `regs->si = 0;` hijack and do not run the `nf_log_trace()` actually.
5. Run the `kretprobe` bpf prog on `ipt_do_table`/`ip6t_do_table`.

## Limit

Currently, it is only able to run on **x86**, not others like **arm**.

It's a little easy to update it to run on **arm**.

## TODO

- [ ] Run on **arm64**.

## Build and run

```bash
# git clone https://github.com/Asphaltt/iptables-trace.git
# cd iptables-trace
# make
# ./iptables-trace -c 20
TIME       SKB                  NETWORK_NS   PID      CPU    INTERFACE          DEST_MAC           IP_LEN PKT_INFO                                               IPTABLES_INFO
[04:53:15] [0xffff8df402e052e8] [4026531840] 6888     3                         00:00:00:00:00:00  264    T_ACK,PSH:192.168.1.138:22->192.168.1.12:53030         ipttrace=[pf=PF_INET in= out=enp0s8 table=filter chain=OUTPUT hook=3 rulenum=1]
[04:53:15] [0xffff8df402e052e8] [4026531840] 6888     3                         00:00:00:00:00:00  264    T_ACK,PSH:192.168.1.138:22->192.168.1.12:53030         iptables=[pf=PF_INET table=filter hook=OUTPUT verdict=ACCEPT cost=77.425µs]
[04:53:15] [0xffff8df50291d200] [4026531840] 8432     1      enp0s8             08:00:27:39:de:94  52     T_PSH:192.168.1.12:53030->192.168.1.138:22             ipttrace=[pf=PF_INET in=enp0s8 out= table=filter chain=INPUT hook=1 rulenum=1]
[04:53:15] [0xffff8df50291d200] [4026531840] 8432     1      enp0s8             08:00:27:39:de:94  52     T_PSH:192.168.1.12:53030->192.168.1.138:22             iptables=[pf=PF_INET table=filter hook=INPUT verdict=ACCEPT cost=36.942µs]
[04:53:15] [0xffff8df402e050e8] [4026531840] 8432     1                         87:ab:0d:ea:d5:19  88     T_ACK,PSH:192.168.1.138:22->192.168.1.12:53030         ipttrace=[pf=PF_INET in= out=enp0s8 table=filter chain=OUTPUT hook=3 rulenum=1]
[04:53:15] [0xffff8df402e050e8] [4026531840] 8432     1                         87:ab:0d:ea:d5:19  88     T_ACK,PSH:192.168.1.138:22->192.168.1.12:53030         iptables=[pf=PF_INET table=filter hook=OUTPUT verdict=ACCEPT cost=40.266µs]
[04:53:15] [0xffff8df402e04ce8] [4026531840] 6888     3                         00:00:00:00:00:00  328    T_ACK,PSH:192.168.1.138:22->192.168.1.12:53030         ipttrace=[pf=PF_INET in= out=enp0s8 table=filter chain=OUTPUT hook=3 rulenum=1]
[04:53:15] [0xffff8df402e04ce8] [4026531840] 6888     3                         00:00:00:00:00:00  328    T_ACK,PSH:192.168.1.138:22->192.168.1.12:53030         iptables=[pf=PF_INET table=filter hook=OUTPUT verdict=ACCEPT cost=84.42µs]
[04:53:15] [0xffff8df50291db00] [4026531840] 8432     1      enp0s8             08:00:27:39:de:94  52     T_PSH:192.168.1.12:53030->192.168.1.138:22             ipttrace=[pf=PF_INET in=enp0s8 out= table=filter chain=INPUT hook=1 rulenum=1]
[04:53:15] [0xffff8df50291db00] [4026531840] 8432     1      enp0s8             08:00:27:39:de:94  52     T_PSH:192.168.1.12:53030->192.168.1.138:22             iptables=[pf=PF_INET table=filter hook=INPUT verdict=ACCEPT cost=38.611µs]
[04:53:15] [0xffff8df50291d000] [4026531840] 8432     1      enp0s8             08:00:27:39:de:94  52     T_PSH:192.168.1.12:53030->192.168.1.138:22             ipttrace=[pf=PF_INET in=enp0s8 out= table=filter chain=INPUT hook=1 rulenum=1]
[04:53:15] [0xffff8df50291d000] [4026531840] 8432     1      enp0s8             08:00:27:39:de:94  52     T_PSH:192.168.1.12:53030->192.168.1.138:22             iptables=[pf=PF_INET table=filter hook=INPUT verdict=ACCEPT cost=40.887µs]
[04:53:15] [0xffff8df50291d900] [4026531840] 8432     1      enp0s8             08:00:27:39:de:94  52     T_PSH:192.168.1.12:53030->192.168.1.138:22             ipttrace=[pf=PF_INET in=enp0s8 out= table=filter chain=INPUT hook=1 rulenum=1]
[04:53:15] [0xffff8df50291d900] [4026531840] 8432     1      enp0s8             08:00:27:39:de:94  52     T_PSH:192.168.1.12:53030->192.168.1.138:22             iptables=[pf=PF_INET table=filter hook=INPUT verdict=ACCEPT cost=48.685µs]
[04:53:15] [0xffff8df402e048e8] [4026531840] 6888     3                         00:00:00:00:00:00  328    T_ACK,PSH:192.168.1.138:22->192.168.1.12:53030         ipttrace=[pf=PF_INET in= out=enp0s8 table=filter chain=OUTPUT hook=3 rulenum=1]
[04:53:15] [0xffff8df402e048e8] [4026531840] 6888     3                         00:00:00:00:00:00  328    T_ACK,PSH:192.168.1.138:22->192.168.1.12:53030         iptables=[pf=PF_INET table=filter hook=OUTPUT verdict=ACCEPT cost=126.368µs]
[04:53:15] [0xffff8df50291df00] [4026531840] 8432     1      enp0s8             08:00:27:39:de:94  52     T_PSH:192.168.1.12:53030->192.168.1.138:22             ipttrace=[pf=PF_INET in=enp0s8 out= table=filter chain=INPUT hook=1 rulenum=1]
[04:53:15] [0xffff8df50291df00] [4026531840] 8432     1      enp0s8             08:00:27:39:de:94  52     T_PSH:192.168.1.12:53030->192.168.1.138:22             iptables=[pf=PF_INET table=filter hook=INPUT verdict=ACCEPT cost=38.087µs]
[04:53:15] [0xffff8df402e050e8] [4026531840] 6888     3                         87:ab:0d:ea:d5:19  1324   T_ACK,PSH:192.168.1.138:22->192.168.1.12:53030         ipttrace=[pf=PF_INET in= out=enp0s8 table=filter chain=OUTPUT hook=3 rulenum=1]
[04:53:15] [0xffff8df402e050e8] [4026531840] 6888     3                         87:ab:0d:ea:d5:19  1324   T_ACK,PSH:192.168.1.138:22->192.168.1.12:53030         iptables=[pf=PF_INET table=filter hook=OUTPUT verdict=ACCEPT cost=40.68µs]
```

The `rulenum` in `ipttrace` is the rule number in `iptables -nvL --line-numbers`.

## License

GPL-3.0 license.
