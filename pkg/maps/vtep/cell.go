// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package vtep

import (
	"log/slog"

	"github.com/cilium/hive/cell"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/maps/registry"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/option"
)

// Cell provides the VTEP map that contains the VTEP device information.
var Cell = cell.Module(
	"vtep-map",
	"eBPF map which contains the VTEP device information",

	cell.Provide(newVTEPMap),
)

func newVTEPMap(lifecycle cell.Lifecycle, logger *slog.Logger, mapSpecRegistry *registry.MapSpecRegistry, metricsRegistry *metrics.Registry) bpf.MapOut[Map] {
	if !option.Config.EnableVTEP {
		return bpf.MapOut[Map]{}
	}

	vtepMap := &vtepMap{
		logger: logger,
	}

	lifecycle.Append(cell.Hook{
		OnStart: func(context cell.HookContext) error {
			spec, err := mapSpecRegistry.Get(MapName)
			if err != nil {
				return err
			}

			vtepMap.bpfMap = bpf.NewMap(spec, &Key{}, &VtepEndpointInfo{}).
				WithCache().WithPressureMetric(metricsRegistry).
				WithEvents(option.Config.GetEventBufferConfig(MapName))

			return vtepMap.init()
		},
		OnStop: func(context cell.HookContext) error {
			return vtepMap.close()
		},
	})

	return bpf.NewMapOut(Map(vtepMap))
}
