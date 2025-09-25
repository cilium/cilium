// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package vtep

import (
	"log/slog"

	"github.com/cilium/hive/cell"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/option"
)

// Cell provides the VTEP map that contains the VTEP device information.
var Cell = cell.Module(
	"vtep-map",
	"eBPF map which contains the VTEP device information",

	cell.Provide(newVTEPMap),
)

func newVTEPMap(lifecycle cell.Lifecycle, logger *slog.Logger, registry *metrics.Registry) bpf.MapOut[Map] {
	if !option.Config.EnableVTEP {
		return bpf.MapOut[Map]{}
	}

	vtepMap := newMap(logger, registry)

	lifecycle.Append(cell.Hook{
		OnStart: func(context cell.HookContext) error {
			return vtepMap.init()
		},
		OnStop: func(context cell.HookContext) error {
			return vtepMap.close()
		},
	})

	return bpf.NewMapOut(Map(vtepMap))
}
