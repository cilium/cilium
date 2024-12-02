// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package nat

import (
	"context"
	"fmt"

	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/promise"
	"github.com/cilium/cilium/pkg/time"
	"github.com/cilium/cilium/pkg/tuple"

	"github.com/cilium/hive/cell"
)

// MapDisabled is the expected error will be if map was not created
// due to configuration.
var MapDisabled = fmt.Errorf("nat map is disabled")

// Cell exposes global nat maps via Hive. These maps depend on
// the final state of EnableNodePort, thus the maps are currently
// provided as promises.
// TODO: Once we have a way of finalizing this config prior to runtime
// we'll want to provide these using bpf.MapOut[T] (GH: #32557)
var Cell = cell.Module(
	"nat-maps",
	"NAT Maps",
	cell.Provide(func(lc cell.Lifecycle, cfgPromise promise.Promise[*option.DaemonConfig]) (promise.Promise[NatMap4], promise.Promise[NatMap6]) {
		var ipv4Nat, ipv6Nat *Map
		res4, promise4 := promise.New[NatMap4]()
		res6, promise6 := promise.New[NatMap6]()

		lc.Append(cell.Hook{
			OnStart: func(hc cell.HookContext) error {
				ctx, cancel := context.WithTimeout(context.Background(), time.Second*60)
				defer cancel()
				cfg, err := cfgPromise.Await(ctx)
				if err != nil {
					return fmt.Errorf("failed to wait for config promise: %w", err)
				}
				if !cfg.EnableNodePort {
					res4.Reject(fmt.Errorf("nat IPv4: %w", MapDisabled))
					res6.Reject(fmt.Errorf("nat IPv6: %w", MapDisabled))
					return nil
				}

				ipv4Nat, ipv6Nat = GlobalMaps(cfg.EnableIPv4,
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
					res4.Reject(MapDisabled)
				}
				if cfg.EnableIPv6 {
					if err := ipv6Nat.Open(); err != nil {
						return fmt.Errorf("open IPv6 nat map: %w", err)
					}
					res6.Resolve(ipv6Nat)
				} else {
					res6.Reject(MapDisabled)
				}
				return nil
			},
			OnStop: func(hc cell.HookContext) error {
				ctx, cancel := context.WithTimeout(context.Background(), time.Minute*5)
				defer cancel()
				cfg, err := cfgPromise.Await(ctx)
				if err != nil {
					return err
				}
				if !cfg.EnableNodePort {
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
