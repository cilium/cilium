// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package nat

import (
	"fmt"

	"github.com/cilium/hive/cell"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/kpr"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/tuple"
)

// ErrMapDisabled is the expected error will be if map was not created
// due to configuration.
var ErrMapDisabled = fmt.Errorf("nat map is disabled")

// Cell exposes global nat maps via Hive.
var Cell = cell.Module(
	"nat-maps",
	"NAT Maps",
	cell.Provide(func(lc cell.Lifecycle, registry *metrics.Registry, cfg *option.DaemonConfig, kprCfg kpr.KPRConfig) (bpf.MapOut[NatMap4], bpf.MapOut[NatMap6]) {
		var out4 bpf.MapOut[NatMap4]
		var out6 bpf.MapOut[NatMap6]
		var ipv4Nat, ipv6Nat *Map

		if !kprCfg.KubeProxyReplacement && !cfg.EnableBPFMasquerade {
			return out4, out6
		}

		ipv4Nat, ipv6Nat = GlobalMaps(registry, cfg.EnableIPv4, cfg.EnableIPv6)
		if ipv4Nat != nil {
			out4 = bpf.NewMapOut[NatMap4](ipv4Nat)
		}
		if ipv6Nat != nil {
			out6 = bpf.NewMapOut[NatMap6](ipv6Nat)
		}

		lc.Append(cell.Hook{
			OnStart: func(hc cell.HookContext) error {
				if ipv4Nat != nil {
					if err := ipv4Nat.OpenOrCreate(); err != nil {
						return fmt.Errorf("open IPv4 nat map: %w", err)
					}
				}
				if ipv6Nat != nil {
					if err := ipv6Nat.OpenOrCreate(); err != nil {
						return fmt.Errorf("open IPv6 nat map: %w", err)
					}
				}
				return nil
			},
			OnStop: func(hc cell.HookContext) error {
				if ipv4Nat != nil {
					if err := ipv4Nat.Map.Close(); err != nil {
						return err
					}
				}
				if ipv6Nat != nil {
					if err := ipv6Nat.Map.Close(); err != nil {
						return err
					}
				}
				return nil
			},
		})

		return out4, out6
	}),
	cell.Provide(provideNATRetriesMap),
)

// NatMap4 describes ipv4 nat map behaviors, used for providing map
// to hive.
type NatMap4 interface {
	NatMap
	DumpBatch4(func(*tuple.TupleKey4, *NatEntry4)) (count int, err error)
}

// NatMap6 describes ipv6 nat map behaviors, used for providing map
// to hive.
type NatMap6 interface {
	NatMap
	DumpBatch6(func(*tuple.TupleKey6, *NatEntry6)) (count int, err error)
}

// NATRetriesMap is a marker interface for the NAT retries map.
// It doesn't provide any functionality to the Cilium Agent because
// the bpf map is only created by the Cilium Agent for the datapath.
// It's still provided to be picked up as dependency by the Loader
// and initialized at startup.
type NATRetriesMap any

func provideNATRetriesMap(lifecycle cell.Lifecycle, daemonConfig *option.DaemonConfig, kprConfig kpr.KPRConfig) bpf.MapOut[NATRetriesMap] {
	if !kprConfig.KubeProxyReplacement && !option.Config.EnableBPFMasquerade {
		return bpf.NewMapOut(NATRetriesMap(nil))
	}

	natRetriesMap := newNATRetriesMap(daemonConfig.IPv4Enabled(), daemonConfig.IPv6Enabled())

	lifecycle.Append(cell.Hook{
		OnStart: func(context cell.HookContext) error {
			return natRetriesMap.init()
		},
		OnStop: func(context cell.HookContext) error {
			// no need to close because the maps are only created for datapath (Create)
			return nil
		},
	})

	return bpf.NewMapOut(NATRetriesMap(natRetriesMap))
}
