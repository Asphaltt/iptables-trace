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

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/perf"
	"github.com/spf13/cobra"
	"golang.org/x/sys/unix"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -no-global-types -cc clang iptablestrace ./ebpf/iptables-trace.c -- -D__TARGET_ARCH_x86 -I./ebpf/headers -Wall

var usage = `examples:
iptables-trace                                      # trace all packets
iptables-trace --proto=icmp -H 1.2.3.4 --icmpid 22  # trace icmp packet with addr=1.2.3.4 and icmpid=22
iptables-trace --proto=tcp  -H 1.2.3.4 -P 22        # trace tcp  packet with addr=1.2.3.4:22
iptables-trace --proto=udp  -H 1.2.3.4 -P 22        # trace udp  packet wich addr=1.2.3.4:22
iptables-trace -t -T -p 1 -P 80 -H 127.0.0.1 --proto=tcp --icmpid=100 -N 10000
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
}

func main() {
	cobra.CheckErr(rootCmd.Execute())
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

	bpfSpec, err := loadIptablestrace()
	if err != nil {
		log.Printf("Failed to load bpf spec: %v", err)
		return
	}

	if err := bpfSpec.RewriteConstants(map[string]interface{}{
		"CFG": getBpfConfig(),
	}); err != nil {
		log.Printf("Failed to rewrite const for config: %v", err)
		return
	}

	var bpfObj iptablestraceObjects
	if err := bpfSpec.LoadAndAssign(&bpfObj, &ebpf.CollectionOptions{
		Programs: ebpf.ProgramOptions{
			LogSize: ebpf.DefaultVerifierLogSize * 10,
		},
	}); err != nil {
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			log.Printf("Failed to load bpf obj: %v\n%-50v", err, ve)
		} else {
			log.Printf("Failed to load bpf obj: %v", err)
		}
		return
	}
	defer bpfObj.Close()

	isHighVersion, err := isKernelVersionGte_5_16()
	if err != nil {
		log.Printf("Failed to check kernel version: %v", err)
		return
	}

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
		}

		fmt.Println(event.output(&ipt, &trace))

		select {
		case <-ctx.Done():
			return
		default:
		}
	}
}
