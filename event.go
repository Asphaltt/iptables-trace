package main

import (
	"fmt"
	"net"
	"strings"
	"time"
	"unsafe"

	"github.com/tklauser/ps"
)

const (
	ethProtoIP   = 0x0800
	ethProtoIPv6 = 0x86DD
)

const (
	ipprotoICMP   = 1
	ipprotoTCP    = 6
	ipprotoUDP    = 17
	ipprotoICMPv6 = 58
)

const (
	routeEventIf            = 0x0001
	routeEventIptable       = 0x0002
	routeEventIptablesTrace = 0x0004
)

var (
	nfVerdictName = []string{
		"DROP",
		"ACCEPT",
		"STOLEN",
		"QUEUE",
		"REPEAT",
		"STOP",
	}

	hookNames = []string{
		"PREROUTING",
		"INPUT",
		"FORWARD",
		"OUTPUT",
		"POSTROUTING",
	}

	tcpFlagNames = []string{
		"CWR",
		"ECE",
		"URG",
		"ACK",
		"PSH",
		"RST",
		"SYN",
		"FIN",
	}
)

func _get(names []string, idx uint32, defaultVal string) string {
	if int(idx) < len(names) {
		return names[idx]
	}

	return defaultVal
}

type l2Info struct {
	DestMac [6]byte
	L3Proto uint16
}

type l3Info struct {
	Saddr     [16]byte
	Daddr     [16]byte
	TotLen    uint16
	IPVersion uint8
	L4Proto   uint8
}

type l4Info struct {
	Sport    uint16
	Dport    uint16
	TCPFlags uint16
	Pad      [2]byte
}

type icmpInfo struct {
	IcmpID   uint16
	IcmpSeq  uint16
	IcmpType uint8
	Pad      [3]byte
}

type iptablesInfo struct {
	TableName [32]byte
	Verdict   uint32
	IptDelay  uint64
	Hook      uint8
	Pf        uint8
	Pad       [2]byte
}

type iptablesTrace struct {
	In        [16]byte
	Out       [16]byte
	TableName [32]byte
	ChainName [32]byte
	RuleNum   uint32
	HookNum   uint32
	Pf        uint8
	Pad       [3]uint8
}

type pktInfo struct {
	Ifname  [16]byte
	Len     uint32
	CPU     uint32
	Pid     uint32
	NetNS   uint32
	PktType uint8
	Pad     [3]byte
}

type perfEvent struct {
	Skb     uint64
	StartNs uint64
	Flags   uint8
	Pad     [3]byte

	pktInfo
	l2Info
	l3Info
	l4Info
	icmpInfo
}

const (
	sizeofEvent = 116 // Note: 116 instead of int(unsafe.Sizeof(perfEvent{})), because of alignment
)

var earliestTs = uint64(0)

func (e *perfEvent) outputTimestamp() string {
	if cfg.Timestamp {
		if earliestTs == 0 {
			earliestTs = e.StartNs
		}
		return fmt.Sprintf("%-7.6f", float64(e.StartNs-earliestTs)/1000000000.0)
	}

	return time.Unix(0, int64(e.StartNs)).Format("15:04:05")
}

func (e *perfEvent) outputTcpFlags() string {
	var flags []string
	tcpFlags := uint8(e.TCPFlags >> 8)
	for i := 0; i < len(tcpFlagNames); i++ {
		if tcpFlags&(1<<i) != 0 {
			flags = append(flags, tcpFlagNames[i])
		}
	}

	return strings.Join(flags, ",")
}

func (e *perfEvent) outputPktInfo() string {
	var saddr, daddr net.IP
	if e.l2Info.L3Proto == ethProtoIP {
		saddr = net.IP(e.Saddr[:4])
		daddr = net.IP(e.Daddr[:4])
	} else {
		saddr = net.IP(e.Saddr[:])
		daddr = net.IP(e.Daddr[:])
	}

	if e.L4Proto == ipprotoTCP {
		tcpFlags := e.outputTcpFlags()
		if tcpFlags == "" {
			return fmt.Sprintf("T:%s:%d->%s:%d",
				saddr, e.Sport, daddr, e.Dport)
		}
		return fmt.Sprintf("T_%s:%s:%d->%s:%d", tcpFlags,
			saddr, e.Sport, daddr, e.Dport)

	} else if e.L4Proto == ipprotoUDP {
		return fmt.Sprintf("U:%s:%d->%s:%d",
			saddr, e.Sport, daddr, e.Dport)
	} else if e.L4Proto == ipprotoICMP || e.L4Proto == ipprotoICMPv6 {
		if e.IcmpType == 8 || e.IcmpType == 128 {
			return fmt.Sprintf("I_request:%s->%s", saddr, daddr)
		} else if e.IcmpType == 0 || e.IcmpType == 129 {
			return fmt.Sprintf("I_reply:%s->%s", saddr, daddr)
		} else {
			return fmt.Sprintf("I:%s->%s", saddr, daddr)
		}
	} else {
		return fmt.Sprintf("%d:%s->%s", e.L4Proto, saddr, daddr)
	}
}

func nullTerminatedStr(b []byte) string {
	off := 0
	for ; off < len(b) && b[off] != 0; off++ {
	}
	b = b[:off]
	return *(*string)(unsafe.Pointer(&b))
}

func (e *perfEvent) outputIptablesInfo(ipt *iptablesInfo, trace *iptablesTrace) string {
	var sb strings.Builder

	if e.Flags&routeEventIptable == routeEventIptable {
		pf := "PF_INET"
		if ipt.Pf == 10 {
			pf = "PF_INET6"
		}

		iptName := nullTerminatedStr(ipt.TableName[:])
		hook := _get(hookNames, uint32(ipt.Hook), fmt.Sprintf("~UNK~[%d]", ipt.Hook))
		verdict := _get(nfVerdictName, ipt.Verdict, fmt.Sprintf("~UNK~[%d]", ipt.Verdict))
		cost := time.Duration(ipt.IptDelay)

		fmt.Fprintf(&sb, "iptables=[pf=%s table=%s hook=%s verdict=%s cost=%s]",
			pf, iptName, hook, verdict, cost)
	}
	if e.Flags&routeEventIptablesTrace == routeEventIptablesTrace {
		pf := "PF_INET"
		if trace.Pf == 10 {
			pf = "PF_INET6"
		}

		in, out := nullTerminatedStr(trace.In[:]), nullTerminatedStr(trace.Out[:])
		table, chain := nullTerminatedStr(trace.TableName[:]), nullTerminatedStr(trace.ChainName[:])

		fmt.Fprintf(&sb, "ipttrace=[pf=%s in=%s out=%s table=%s chain=%s hook=%d rulenum=%d]",
			pf, in, out, table, chain, trace.HookNum, trace.RuleNum)
	}

	return sb.String()
}

func (e *perfEvent) getProcessName(pid int) string {
	p, err := ps.FindProcess(pid)
	if err != nil {
		return ""
	}

	return p.Command()
}

func printHeader() {
	fmt.Printf("%-10s %-16s %-6s %s\t%s\n",
		"TIME", "INTERFACE", "CPU", "PACKET", "PROCESS")
}

func (e *perfEvent) output(ipt *iptablesInfo, trace *iptablesTrace) string {
	var s strings.Builder

	// time
	t := e.outputTimestamp()
	s.WriteString(fmt.Sprintf("[%-8s] ", t))

	// interface
	ifname := nullTerminatedStr(e.Ifname[:])
	s.WriteString(fmt.Sprintf("%-16s ", ifname))

	// cpu
	s.WriteString(fmt.Sprintf("%-6d ", e.CPU))

	// pkt info
	pktInfo := e.outputPktInfo()
	s.WriteString(fmt.Sprintf("%s\t ", pktInfo))

	// pid
	s.WriteString(fmt.Sprintf("%d(%s)\t", e.Pid, e.getProcessName(int(e.Pid))))

	// iptables info
	iptablesInfo := e.outputIptablesInfo(ipt, trace)
	s.WriteString(iptablesInfo)

	return s.String()
}
