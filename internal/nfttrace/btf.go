// Copyright 2025 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package nfttrace

import (
	"errors"

	"github.com/Asphaltt/mybtf"
	"github.com/cilium/ebpf/btf"
)

var ErrNotFound = errors.New("not found")

func isNftTracePacketNew(spec *btf.Spec) (bool, error) {
	iter := spec.Iterate()
	for iter.Next() {
		v, ok := iter.Type.(*btf.Func)
		if !ok {
			continue
		}

		fnName := v.Name
		if fnName != "__nft_trace_packet" {
			continue
		}

		proto := v.Type.(*btf.FuncProto)
		if len(proto.Params) != 5 {
			return false, nil
		}

		return proto.Params[0].Name == "pkt" && mybtf.IsStructPointer(proto.Params[0].Type, "nft_pktinfo"), nil
	}

	return false, ErrNotFound
}

func IsNftTracePacketNew(spec *btf.Spec) (bool, error) {
	isNew, err := isNftTracePacketNew(spec)
	if err == nil {
		return isNew, nil
	}

	spec, err = btf.LoadKernelModuleSpec("nf_tables")
	if err != nil {
		return false, err
	}

	return isNftTracePacketNew(spec)
}
