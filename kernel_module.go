package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/cilium/ebpf"
)

const bpffsRoot = "/sys/fs/bpf/iptables-trace"

func b2int(b bool) int {
	if b {
		return 1
	}
	return 0
}

func pinProg(p *ebpf.Program, name string) (string, error) {
	pinPath := filepath.Join(bpffsRoot, name)
	err := p.Pin(pinPath)
	return pinPath, err
}

func unpinAll(progs ...*ebpf.Program) {
	for _, p := range progs {
		p.Unpin()
	}
}

// func insmod(isKernelVersionGte_5_16 bool, kprobe, kretprobe, trace *ebpf.Program) error {
// 	out, err := exec.Command("insmod",
// 		"./kernel/iptables-trace.ko",
// 		fmt.Sprintf("bpf_prog_entry_fd=%d", kprobe.FD()),
// 		fmt.Sprintf("bpf_prog_exit_fd=%d", kretprobe.FD()),
// 		fmt.Sprintf("bpf_prog_trace_fd=%d", trace.FD()),
// 		fmt.Sprintf("version_gte_5_16=%d", b2int(isKernelVersionGte_5_16)),
// 	).CombinedOutput()
// 	if err != nil {
// 		return fmt.Errorf("failed to insmod iptables-trace.ko: %w\n%s", err, string(out))
// 	}

// 	return nil
// }

func insmod(isKernelVersionGte_5_16 bool, kprobe, kretprobe, trace *ebpf.Program) error {
	_ = os.MkdirAll(bpffsRoot, 0o755)
	entryPath, err := pinProg(kprobe, "entry")
	if err != nil {
		return fmt.Errorf("failed to pin entry bpf prog: %w", err)
	}
	exitPath, err := pinProg(kretprobe, "exit")
	if err != nil {
		unpinAll(kprobe)
		return fmt.Errorf("failed to pin exit bpf prog: %w", err)
	}
	tracePath, err := pinProg(trace, "trace")
	if err != nil {
		unpinAll(kprobe, kretprobe)
		return fmt.Errorf("failed to pin trace bpf prog: %w", err)
	}

	os.Chdir("kernel")
	defer os.Chdir("..")

	out, err := exec.Command("insmod",
		"iptables-trace.ko",
		fmt.Sprintf("bpf_prog_entry_path=%s", entryPath),
		fmt.Sprintf("bpf_prog_exit_path=%s", exitPath),
		fmt.Sprintf("bpf_prog_trace_path=%s", tracePath),
		fmt.Sprintf("version_gte_5_16=%d", b2int(isKernelVersionGte_5_16)),
	).CombinedOutput()
	if err != nil {
		unpinAll(kprobe, kretprobe, trace)
		return fmt.Errorf("failed to insmod iptables-trace.ko: %w\n%s", err, string(out))
	}

	return nil
}

func rmmod() error {
	return exec.Command("rmmod", "iptables-trace").Run()
}
