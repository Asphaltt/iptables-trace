package main

import (
	"encoding/binary"
	"fmt"
	"net"
)

// Config is the configurations for the bpf program.
type Config struct {
	CatchCount   uint64
	IP           string
	ip           uint32
	Proto        string
	proto        uint8
	IcmpID       uint16
	Port         uint16
	Pid          uint32
	NetNS        uint32
	Time         bool
	Timestamp    bool
	PerCPUBuffer int
	Gops         string
}

var cfg Config

func init() {
	fs := rootCmd.PersistentFlags()
	fs.StringVarP(&cfg.IP, "ipaddr", "H", "", "ip address")
	fs.StringVar(&cfg.Proto, "proto", "", "tcp|udp|icmp|any")
	fs.Uint16Var(&cfg.IcmpID, "icmpid", 0, "trace icmp id")
	fs.Uint64VarP(&cfg.CatchCount, "catch-count", "c", 0, "catch and print count")
	fs.Uint16VarP(&cfg.Port, "port", "P", 0, "udp or tcp port")
	fs.Uint32VarP(&cfg.Pid, "pid", "p", 0, "trace this PID only")
	fs.Uint32VarP(&cfg.NetNS, "netns", "N", 0, "trace this netns inode only")
	fs.BoolVarP(&cfg.Time, "time", "T", true, "show HH:MM:SS timestamp")
	fs.BoolVarP(&cfg.Timestamp, "timestamp", "t", false, "show timestamp in seconds at us resolution")
	fs.IntVarP(&cfg.PerCPUBuffer, "per-cpu-buffer", "B", 4096, "per CPU buffer to receive perf event")
	fs.StringVar(&cfg.Gops, "gops", "", "gops address")
}

func (c *Config) parse() error {
	ip := c.IP
	if ip != "" {
		ip := net.ParseIP(ip)
		ip = ip.To4()
		if ip == nil {
			return fmt.Errorf("invalid IPv4 addr(%s)", ip)
		}

		c.ip = binary.BigEndian.Uint32(ip)
	}

	proto := c.Proto
	if proto != "" {
		switch proto {
		case "tcp":
			c.proto = 6
		case "udp":
			c.proto = 17
		case "icmp":
			c.proto = 1
		case "any":
		default:
			return fmt.Errorf("invalid proto(%s)", proto)
		}
	}

	return nil
}
