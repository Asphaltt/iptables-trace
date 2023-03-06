package main

type BpfConfig struct {
	NetNS  uint32
	Pid    uint32
	IP     uint32
	Port   uint16
	IcmpID uint16
	Proto  uint8
	Pad    [3]uint8
}

func getBpfConfig() BpfConfig {
	return BpfConfig{
		NetNS:  cfg.NetNS,
		Pid:    cfg.Pid,
		IP:     cfg.ip,
		Port:   (cfg.Port >> 8) & (cfg.Port << 8),
		IcmpID: (cfg.IcmpID >> 8) & (cfg.IcmpID << 8),
		Proto:  cfg.proto,
	}
}
