// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package main

import (
	"unsafe"

	"github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"

	"github.com/cilium/cilium/pkg/ebpf"
	"github.com/cilium/cilium/pkg/hive/cell"
)

type exampleMap struct{ *ebpf.Map }

func newExampleMap(lc cell.Lifecycle, log logrus.FieldLogger) exampleMap {
	e := exampleMap{
		Map: ebpf.NewMap(&ebpf.MapSpec{
			Name:       "example",
			Type:       ebpf.Hash,
			KeySize:    uint32(unsafe.Sizeof(ExampleKey{})),
			ValueSize:  uint32(unsafe.Sizeof(ExampleValue{})),
			MaxEntries: 1000000,
			Flags:      unix.BPF_F_NO_PREALLOC,
			Pinning:    ebpf.PinByName,
		})}
	lc.Append(cell.Hook{
		OnStart: func(cell.HookContext) error {
			return e.OpenOrCreate()
		},
	})
	return e
}
