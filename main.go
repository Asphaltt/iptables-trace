package main

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/Asphaltt/iptables-trace/internal/assert"
	"github.com/Asphaltt/iptables-trace/internal/ipttrace"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"github.com/spf13/cobra"
	"golang.org/x/sys/unix"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -no-global-types -cc clang iptablestrace ./ebpf/iptables-trace.c -- -D__TARGET_ARCH_x86 -I./ebpf/headers -Wall

var usage = `examples:
iptables-trace                                      # trace all packets
iptables-trace --proto=icmp -H 1.2.3.4 --icmpid 22  # trace icmp packet with addr=1.2.3.4 and icmpid=22
iptables-trace --proto=tcp  -H 1.2.3.4 -P 22        # trace tcp  packet with addr=1.2.3.4:22
iptables-trace --proto=udp  -H 1.2.3.4 -P 22        # trace udp  packet with addr=1.2.3.4:22
iptables-trace -t -T -p 1 -P 80 -H 127.0.0.1 --proto=tcp --icmpid=100 -N 10000

options:
`

var rootCmd = cobra.Command{
	Use:   "iptables-trace",
	Short: "Trace any packet through iptables",
	Long:  usage,
	Run: func(cmd *cobra.Command, args []string) {
		if err := cfg.parse(); err != nil {
			fmt.Println(err)
			return
		}

		runGops()
		runEbpf()
	},
	DisableFlagsInUseLine: true,
}

func main() {
	assert.NoErr(rootCmd.Execute(), "Error: %v")
}

// runEbpf attaches the kprobes and prints the kprobes' info.
func runEbpf() {
	if err := unix.Setrlimit(unix.RLIMIT_NOFILE, &unix.Rlimit{
		Cur: 4096,
		Max: 4096,
	}); err != nil {
		log.Fatalf("failed to set temporary rlimit: %s", err)
	}
	if err := unix.Setrlimit(unix.RLIMIT_MEMLOCK, &unix.Rlimit{
		Cur: unix.RLIM_INFINITY,
		Max: unix.RLIM_INFINITY,
	}); err != nil {
		log.Fatalf("Failed to set temporary rlimit: %s", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	btfSpec, err := btf.LoadKernelSpec()
	assert.NoErr(err, "Failed to load kernel btf spec: %v")

	kernelModules := map[string]*btf.Spec{}
	iptBtfSpec, _ := btf.LoadKernelModuleSpec("ip_tables")
	if iptBtfSpec != nil {
		kernelModules["ip_tables"] = iptBtfSpec
	}
	nftBtfSpec, _ := btf.LoadKernelModuleSpec("nf_tables")
	if nftBtfSpec != nil {
		kernelModules["nf_tables"] = nftBtfSpec
	}

	bpfSpec, err := loadIptablestrace()
	if err != nil {
		log.Printf("Failed to load bpf spec: %v", err)
		return
	}

	err = bpfSpec.Variables["CFG"].Set(getBpfConfig())
	assert.NoErr(err, "Failed to set bpf config: %v")

	var bpfObj iptablestraceObjects
	err = bpfSpec.LoadAndAssign(&bpfObj, &ebpf.CollectionOptions{
		Programs: ebpf.ProgramOptions{
			KernelTypes:       btfSpec,
			KernelModuleTypes: kernelModules,
		},
	})
	assert.NoVerifierErr(err, "Failed to load and assign bpf objects: %v")
	defer bpfObj.Close()

	kprobeNft, err := link.Kprobe("nft_do_chain", bpfObj.K_nftDoChain, nil)
	assert.NoErr(err, "Failed to attach kprobe nft_do_chain: %v")
	defer kprobeNft.Close()

	kretprobeNft, err := link.Kretprobe("nft_do_chain", bpfObj.KrNftDoChain, nil)
	assert.NoErr(err, "Failed to attach kretprobe nft_do_chain: %v")
	defer kretprobeNft.Close()

	isHighVersion, err := ipttrace.IsIptDoTableNew(btfSpec)
	if err != nil && errors.Is(err, ipttrace.ErrNotFound) {
		log.Fatalln("ipt_do_table not found in kernel btf spec")
	}
	assert.NoErr(err, "Failed to check ipt_do_table btf spec: %v")

	kIptDoTable := bpfObj.K_iptDoTable
	if !isHighVersion {
		kIptDoTable = bpfObj.K_iptDoTableOld
	}

	if err := insmod(isHighVersion, kIptDoTable, bpfObj.KrIptDoTable, bpfObj.K_nfLogTrace); err != nil {
		log.Printf("Failed to insmod: %v", err)
		return
	}
	defer func() {
		unpinAll(kIptDoTable, bpfObj.KrIptDoTable, bpfObj.K_nfLogTrace)

		select {
		case <-ctx.Done():
		default:
			if err := rmmod(); err != nil {
				log.Printf("Failed to rmmod iptables-trace: %v\nPlease run `sudo rmmod iptables-trace` by hand!", err)
			}
		}
	}()

	rd, err := perf.NewReader(bpfObj.SkbtracerEvent, cfg.PerCPUBuffer)
	if err != nil {
		log.Printf("Failed to create perf event reader: %v", err)
		return
	}
	defer func() {
		select {
		case <-ctx.Done():
		default:
			_ = rd.Close()
		}
	}()

	go func() {
		<-ctx.Done()

		if err := rmmod(); err != nil {
			log.Printf("Failed to rmmod iptables-trace: %v\nPlease run `sudo rmmod iptables-trace` by hand!", err)
		}

		_ = rd.Close()

		log.Println("Received signal, exiting program...")
	}()

	printHeader()

	var event perfEvent
	var ipt iptablesInfo
	var trace iptablesTrace
	var nft nftTrace

	forever := cfg.CatchCount == 0
	for n := cfg.CatchCount; forever || n > 0; n-- {
		record, err := rd.Read()
		if err != nil {
			if errors.Is(err, perf.ErrClosed) {
				return
			}
			log.Printf("Reading from perf event reader: %v", err)
			return
		}

		if record.LostSamples != 0 {
			log.Printf("Perf event ring buffer full, dropped %d samples", record.LostSamples)
		}

		if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event); err != nil {
			log.Printf("Failed to parse perf event: %v", err)
			continue
		}

		if event.Flags&routeEventIptable == routeEventIptable {
			if err := binary.Read(bytes.NewReader(record.RawSample[sizeofEvent:]), binary.LittleEndian, &ipt); err != nil {
				log.Printf("Failed to parse iptables info: %v", err)
				continue
			}
		} else if event.Flags&routeEventIptablesTrace == routeEventIptablesTrace {
			if err := binary.Read(bytes.NewReader(record.RawSample[sizeofEvent:]), binary.LittleEndian, &trace); err != nil {
				log.Printf("Failed to parse iptables trace: %v", err)
				continue
			}
		} else if event.Flags&routeEventNftChain == routeEventNftChain {
			if err := binary.Read(bytes.NewReader(record.RawSample[sizeofEvent:]), binary.LittleEndian, &nft); err != nil {
				log.Printf("Failed to parse nft trace: %v", err)
				continue
			}
		}

		fmt.Println(event.output(&ipt, &trace, &nft))

		select {
		case <-ctx.Done():
			return
		default:
		}
	}
}
