// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ipmasq

import (
	"fmt"

	"github.com/cilium/hive/cell"

	"github.com/cilium/cilium/pkg/bpf"
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
}

func newIPMasqMaps(p ipMasqMapsParams) bpf.MapOut[*IPMasqBPFMap] {
	m := &IPMasqBPFMap{MetricsRegistry: p.MetricsRegistry}

	p.Lifecycle.Append(cell.Hook{
		OnStart: func(cell.HookContext) error {
			if option.Config.EnableIPMasqAgent {
				if option.Config.EnableIPv4Masquerade {
					if err := IPMasq4Map(p.MetricsRegistry).OpenOrCreate(); err != nil {
						return fmt.Errorf("initializing IPv4 masquerading map: %w", err)
					}
				}
				if option.Config.EnableIPv6Masquerade {
					if err := IPMasq6Map(p.MetricsRegistry).OpenOrCreate(); err != nil {
						return fmt.Errorf("initializing IPv6 masquerading map: %w", err)
					}
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
