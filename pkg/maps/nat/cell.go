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
	"github.com/cilium/cilium/pkg/promise"
	"github.com/cilium/cilium/pkg/tuple"
)

// ErrMapDisabled is the expected error will be if map was not created
// due to configuration.
var ErrMapDisabled = fmt.Errorf("nat map is disabled")

// Cell exposes global nat maps via Hive. These maps depend on
// the final state of EnableBPFMasquerade, thus the maps are currently
// provided as promises.
// TODO: Once we have a way of finalizing this config prior to runtime
// we'll want to provide these using bpf.MapOut[T] (GH: #32557)
var Cell = cell.Module(
	"nat-maps",
	"NAT Maps",
	cell.Provide(func(lc cell.Lifecycle, registry *metrics.Registry, cfg *option.DaemonConfig, kprCfg kpr.KPRConfig) (promise.Promise[NatMap4], promise.Promise[NatMap6]) {
		var ipv4Nat, ipv6Nat *Map
		res4, promise4 := promise.New[NatMap4]()
		res6, promise6 := promise.New[NatMap6]()

		lc.Append(cell.Hook{
			OnStart: func(hc cell.HookContext) error {
				if !kprCfg.KubeProxyReplacement && !cfg.EnableBPFMasquerade {
					res4.Reject(fmt.Errorf("nat IPv4: %w", ErrMapDisabled))
					res6.Reject(fmt.Errorf("nat IPv6: %w", ErrMapDisabled))
					return nil
				}

				ipv4Nat, ipv6Nat = GlobalMaps(registry, cfg.EnableIPv4,
					cfg.EnableIPv6, true)

				// Maps are still created before DaemonConfig promise is resolved in
				// daemon.initMaps(...) under the same circumstances
				// so we just open them here so they can be provided to hive.
				//
				// TODO: Refactor ctmap gc Enable() such that it can use the map descriptors from
				// here so we can move all nat map creation logic into here.
				// NOTE: This code runs concurrently with startDaemon(), so if any dependency to
				// daemon having finished endpoint restore, for example, is added, we should
				// await for an appropriate promise.
				if cfg.EnableIPv4 {
					if err := ipv4Nat.Open(); err != nil {
						return fmt.Errorf("open IPv4 nat map: %w", err)
					}
					res4.Resolve(ipv4Nat)
				} else {
					res4.Reject(ErrMapDisabled)
				}
				if cfg.EnableIPv6 {
					if err := ipv6Nat.Open(); err != nil {
						return fmt.Errorf("open IPv6 nat map: %w", err)
					}
					res6.Resolve(ipv6Nat)
				} else {
					res6.Reject(ErrMapDisabled)
				}
				return nil
			},
			OnStop: func(hc cell.HookContext) error {
				if !kprCfg.KubeProxyReplacement && !cfg.EnableBPFMasquerade {
					return nil
				}

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

		return promise4, promise6
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
