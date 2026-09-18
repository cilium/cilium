// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ipcache

import (
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net/netip"

	"github.com/cilium/hive/cell"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/promise"
)

// Cell provides the ipcache BPF map as a bpf.MapOut.
var Cell = cell.Module(
	"ipcache-map",
	"eBPF map which maps IP prefixes to security identities",

	cell.Provide(newIPCacheMapCell),
)

type ipcacheMapParams struct {
	cell.In

	Logger          *slog.Logger
	Lifecycle       cell.Lifecycle
	DaemonConfig    *option.DaemonConfig
	MetricsRegistry *metrics.Registry
}

type ipcacheMapOut struct {
	cell.Out

	bpf.MapOut[*Map]

	// RestoredPrefixes is a promise of the IP prefix to security identity
	// mappings that are read from the previous ipcache map that is restored
	// upon startup.
	RestoredPrefixes promise.Promise[map[netip.Prefix]identity.NumericIdentity]
}

func newIPCacheMapCell(params ipcacheMapParams) ipcacheMapOut {
	m := IPCacheMap(params.MetricsRegistry)
	resolver, restored := promise.New[map[netip.Prefix]identity.NumericIdentity]()

	params.Lifecycle.Append(cell.Hook{
		OnStart: func(cell.HookContext) error {
			var localPrefixes map[netip.Prefix]identity.NumericIdentity
			if !params.DaemonConfig.DryMode {
				if params.DaemonConfig.RestoreState {
					// Read the old map before it is recreated below, so the
					// ipcache cell can restore its local identities.
					var err error
					if localPrefixes, err = dumpLocalPrefixes(m); err != nil {
						params.Logger.Warn("Failed to dump existing identities from the previous ipcache. This may cause policy interruptions during restart.", logfields.Error, err)
						// continue; we may have a partial dump
					}
					params.Logger.Debug("dumped ipcache with local identities", logfields.Count, len(localPrefixes))
				}

				// The ipcache is shared between endpoints. Unpin the old ipcache map created
				// by any previous instances of the agent to prevent new endpoints from
				// picking up the old map pin. The old ipcache will continue to be used by
				// loaded bpf programs, it will just no longer be updated by the agent.
				//
				// This is to allow existing endpoints that have not been regenerated yet to
				// continue using the existing ipcache until the endpoint is regenerated for
				// the first time and its bpf programs have been replaced. Existing endpoints
				// are using a policy map which is potentially out of sync as local identities
				// are re-allocated on startup.
				if err := m.Recreate(); err != nil {
					return fmt.Errorf("initializing ipcache map: %w", err)
				}
			}

			resolver.Resolve(localPrefixes)
			return nil
		},
		OnStop: func(cell.HookContext) error {
			return m.Close()
		},
	})

	return ipcacheMapOut{
		MapOut:           bpf.NewMapOut(m),
		RestoredPrefixes: restored,
	}
}

// dumpLocalPrefixes returns any prefixes with a locally-scoped or ingress
// identity from the soon-to-be-overwritten ipcache BPF map.
func dumpLocalPrefixes(m *Map) (map[netip.Prefix]identity.NumericIdentity, error) {
	localPrefixes := map[netip.Prefix]identity.NumericIdentity{}
	err := m.DumpWithCallback(func(key bpf.MapKey, value bpf.MapValue) {
		k := key.(*Key)
		v := value.(*RemoteEndpointInfo)
		nid := identity.NumericIdentity(v.SecurityIdentity)

		if !v.TunnelEndpoint.IsZero() || k.ClusterID != 0 {
			return
		}

		if nid.Scope() == identity.IdentityScopeLocal || nid == identity.ReservedIdentityIngress {
			localPrefixes[k.Prefix()] = nid
		}
	})
	// DumpWithCallback leaves the map open, so close it before Recreate opens
	// it again.
	m.Close()

	// ignore non-existent cache
	if errors.Is(err, fs.ErrNotExist) {
		return localPrefixes, nil
	}
	return localPrefixes, err
}
