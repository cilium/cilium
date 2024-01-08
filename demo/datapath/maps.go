package datapath

import (
	"github.com/cilium/cilium/pkg/ebpf"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
)

var mapsCell = cell.Module(
	"maps",
	"Demo BPF maps",

	cell.Provide(
		newFrontendsMap,
		newBackendsMap,
	),
)

type (
	frontendsMap struct{ *ebpf.Map }
	backendsMap  struct{ *ebpf.Map }
)

func newFrontendsMap(lc hive.Lifecycle, log logrus.FieldLogger) frontendsMap {
	e := frontendsMap{
		Map: ebpf.NewMap(&ebpf.MapSpec{
			Name:       "frontends",
			Type:       ebpf.Hash,
			KeySize:    uint32(IDSize),
			ValueSize:  uint32(maxFrontendSize),
			MaxEntries: 10000,
			Flags:      unix.BPF_F_NO_PREALLOC,
			Pinning:    ebpf.PinByName,
		})}
	lc.Append(hive.Hook{
		OnStart: func(hive.HookContext) error {
			return e.OpenOrCreate()
		},
	})
	return e
}

func newBackendsMap(lc hive.Lifecycle, log logrus.FieldLogger) backendsMap {
	e := backendsMap{
		Map: ebpf.NewMap(&ebpf.MapSpec{
			Name:       "backends",
			Type:       ebpf.Hash,
			KeySize:    uint32(IDSize),
			ValueSize:  uint32(backendSize),
			MaxEntries: 10000,
			Flags:      unix.BPF_F_NO_PREALLOC,
			Pinning:    ebpf.PinByName,
		})}
	lc.Append(hive.Hook{
		OnStart: func(hive.HookContext) error {
			return e.OpenOrCreate()
		},
	})
	return e
}
