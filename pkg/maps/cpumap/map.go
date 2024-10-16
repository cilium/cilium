// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cpumap

import (
	"fmt"
	"unsafe"

	"github.com/cilium/hive/cell"

	"github.com/cilium/cilium/pkg/bpf"
	dpcfgdef "github.com/cilium/cilium/pkg/datapath/linux/config/defines"
	"github.com/cilium/cilium/pkg/ebpf"
)

const (
	CPUMapName = "cilium_cpu_map"
)

// cpuMapValue is a representation of the value in an eBPF CPU map.
// This representation changed in 2020 with the introduction of allowing
// for eBPF programs to be attached to map entries, allowing for chaining
// XDP programs together. This use case is not supported as of right now,
// therefore the field is unused.
//
// For more information, see
// https://lore.kernel.org/bpf/5c9febdf903d810b3415732e5cd98491d7d9067a.1594734381.git.lorenzo@kernel.org/
type cpuMapValue struct {
	QSize   uint32             `align:"qsize"`
	BpfProg struct{ Fd int32 } `align:"bpf_prog"`
}

// CPUMap is a high level interface for working with the XDP cpumap.
// There are no user interactions that need to happen on the CPUMap,
// therefore the interface is empty.
type CPUMap interface{}

// cpuMap is the internal implementation of the CPUMap interface.
type cpuMap struct {
	m   *ebpf.Map
	cfg Config
}

// Populate should be called on hive startup to populate the CPUMap
// with entries for each CPU.
func (c *cpuMap) Populate() error {
	// Sanity checks
	if !c.cfg.enabled {
		return fmt.Errorf("Populate called on CPUMap when it is disabled")
	}

	ncpus := uint32(c.cfg.NumCPUs())
	maxEntries := c.m.MaxEntries()
	if uint32(c.cfg.NumCPUs()) != c.m.MaxEntries() {
		return fmt.Errorf("the number of configured cpus does not match the number of entries in the cpumap: %d != %d", ncpus, maxEntries)
	}

	for i := 0; i < int(maxEntries); i++ {
		if err := c.m.Put(
			uint32(i),
			cpuMapValue{QSize: uint32(c.cfg.QSize())},
		); err != nil {
			return fmt.Errorf("unable to populate cpumap on entry with index %d: %w", i, err)
		}
	}

	return nil
}

// createCPUMap constructs the internal cpuMap implementation from the given
// configurables.
func createCPUMap(lc cell.Lifecycle, cfg Config, pinning ebpf.PinType) *cpuMap {
	m := ebpf.NewMap(&ebpf.MapSpec{
		Name:       CPUMapName,
		Type:       ebpf.CPUMap,
		KeySize:    4, // 32-bit integer is four bytes
		ValueSize:  uint32(unsafe.Sizeof(cpuMapValue{})),
		MaxEntries: uint32(cfg.NumCPUs()),
		Pinning:    pinning,
		Flags:      0,
	})

	c := &cpuMap{m: m, cfg: cfg}

	lc.Append(cell.Hook{
		OnStart: func(cell.HookContext) error {
			// Sanity check, useful for testing.
			if !cfg.enabled {
				return nil
			}
			if err := m.OpenOrCreate(); err != nil {
				return fmt.Errorf("failed to init cpumap: %w", err)
			}
			if err := c.Populate(); err != nil {
				return fmt.Errorf("unable to populate cpumap: %w", err)
			}

			return nil
		},
		OnStop: func(_ cell.HookContext) error {
			if err := m.Close(); err != nil {
				return fmt.Errorf("unable to close cpumap: %w", err)
			}
			return nil
		},
	})

	return c
}

// newCPUMapIn holds the dependencies required to create the cpumap.
type newCPUMapIn struct {
	cell.In
	Lifecycle cell.Lifecycle
	Config    Config
}

// newCPUMapOut holds the items that are injected into the hive. This
// includes the eBPF map representation and the C Defines that contain
// map metadata.
type newCPUMapOut struct {
	cell.Out

	MapOut  bpf.MapOut[CPUMap]
	NodeOut dpcfgdef.NodeOut
}

// newCPUMap is a hive constructor for the CPUMap.
func newCPUMap(in newCPUMapIn) newCPUMapOut {
	out := newCPUMapOut{}

	if !in.Config.enabled {
		return out
	}

	out.NodeOut.NodeDefines = map[string]string{
		"ENABLE_CPU_MAP": "1",
		"CPU_MAP":        CPUMapName,
	}

	out.MapOut = bpf.NewMapOut(CPUMap(
		createCPUMap(in.Lifecycle, in.Config, ebpf.PinByName),
	))

	return out
}
