// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package vtep

import (
	"fmt"
	"log/slog"

	"github.com/cilium/hive/cell"
	"golang.org/x/sys/unix"

	"github.com/cilium/cilium/pkg/bpf"
	mapregistry "github.com/cilium/cilium/pkg/maps/registry"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/option"
)

// Cell provides the VTEP map that contains the VTEP device information.
var Cell = cell.Module(
	"vtep-map",
	"eBPF map which contains the VTEP device information",

	cell.Provide(newVTEPMap),
	cell.Invoke(configure),
)

func newVTEPMap(lifecycle cell.Lifecycle, logger *slog.Logger, metrics *metrics.Registry, reg *mapregistry.MapRegistry) bpf.MapOut[Map] {
	if !option.Config.EnableVTEP {
		return bpf.MapOut[Map]{}
	}

	vtepMap := &vtepMap{logger: logger}

	lifecycle.Append(cell.Hook{
		OnStart: func(context cell.HookContext) error {
			var err error
			vtepMap.bpfMap, err = bpf.NewMapFromRegistry(reg, MapName, &Key{}, &VtepEndpointInfo{})
			if err != nil {
				return fmt.Errorf("create VTEP map from registry: %w", err)
			}
			vtepMap.bpfMap.WithCache().WithPressureMetric(metrics).
				WithEvents(option.Config.GetEventBufferConfig(MapName))
			return vtepMap.init()
		},
		OnStop: func(context cell.HookContext) error {
			return vtepMap.close()
		},
	})

	return bpf.NewMapOut(Map(vtepMap))
}

func configure(reg *mapregistry.MapRegistry) error {
	flags := uint32(unix.BPF_F_RDONLY_PROG)
	if !option.Config.PreAllocateMaps {
		flags |= unix.BPF_F_NO_PREALLOC
	}

	return reg.Modify(MapName, func(m *mapregistry.MapSpecPatch) {
		m.Flags = flags
	})
}
