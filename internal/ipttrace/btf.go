// Copyright 2025 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package ipttrace

import (
	"errors"

	"github.com/Asphaltt/mybtf"
	"github.com/cilium/ebpf/btf"
)

var ErrNotFound = errors.New("not found")

func isIptDoTableNew(spec *btf.Spec) (bool, error) {
	iter := spec.Iterate()
	for iter.Next() {
		v, ok := iter.Type.(*btf.Func)
		if !ok {
			continue
		}

		fnName := v.Name
		if fnName != "ipt_do_table" {
			continue
		}

		proto := v.Type.(*btf.FuncProto)
		if len(proto.Params) != 3 {
			return false, errors.New("unexpected number of parameters")
		}

		return proto.Params[0].Name == "priv" && mybtf.IsVoidPointer(proto.Params[0].Type), nil
	}

	return false, ErrNotFound
}

func IsIptDoTableNew(spec *btf.Spec) (bool, error) {
	isNew, err := isIptDoTableNew(spec)
	if err == nil {
		return isNew, nil
	}

	spec, err = btf.LoadKernelModuleSpec("ip_tables")
	if err != nil {
		return false, err
	}

	return isIptDoTableNew(spec)
}
