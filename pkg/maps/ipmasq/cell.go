// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ipmasq

import (
	"fmt"

	"github.com/cilium/hive/cell"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/maps/registry"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/option"
)

var Cell = cell.Module(
	"ip-masq-maps",
	"BPF ip-masq-agent maps",

	cell.Provide(newIPMasqMaps),
)

type ipMasqMapsParams struct {
	cell.In

	Lifecycle       cell.Lifecycle
	MetricsRegistry *metrics.Registry
	MapSpecRegistry *registry.MapSpecRegistry
}

func newIPMasqMaps(p ipMasqMapsParams) bpf.MapOut[*IPMasqBPFMap] {
	m := &IPMasqBPFMap{}

	if !option.Config.EnableIPMasqAgent {
		return bpf.NewMapOut(m)
	}

	p.Lifecycle.Append(cell.Hook{
		OnStart: func(cell.HookContext) error {
			if option.Config.EnableIPv4Masquerade {
				spec, err := p.MapSpecRegistry.Get(MapNameIPv4)
				if err != nil {
					return fmt.Errorf("getting IPv4 masquerading map spec: %w", err)
				}

				m.ipMasq4Map = bpf.NewMap(spec, &Key4{}, &Value{}).
					WithCache().WithPressureMetric(p.MetricsRegistry).
					WithEvents(option.Config.GetEventBufferConfig(MapNameIPv4))

				if err := m.ipMasq4Map.OpenOrCreate(); err != nil {
					return fmt.Errorf("initializing IPv4 masquerading map: %w", err)
				}
			}
			if option.Config.EnableIPv6Masquerade {
				spec, err := p.MapSpecRegistry.Get(MapNameIPv6)
				if err != nil {
					return fmt.Errorf("getting IPv6 masquerading map spec: %w", err)
				}

				m.ipMasq6Map = bpf.NewMap(spec, &Key6{}, &Value{}).
					WithCache().WithPressureMetric(p.MetricsRegistry).
					WithEvents(option.Config.GetEventBufferConfig(MapNameIPv6))

				if err := m.ipMasq6Map.OpenOrCreate(); err != nil {
					return fmt.Errorf("initializing IPv6 masquerading map: %w", err)
				}
			}
			return nil
		},
		OnStop: func(cell.HookContext) error {
			// No clean-up required for the ip-masq-agent maps at shutdown.
			return nil
		},
	})

	return bpf.NewMapOut(m)
}
