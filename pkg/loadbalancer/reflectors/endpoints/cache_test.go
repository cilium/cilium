// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package endpoints

import (
	"slices"
	"testing"

	"github.com/stretchr/testify/require"

	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/k8s"
	"github.com/cilium/cilium/pkg/loadbalancer"
)

func backendWithPorts(ports ...uint16) *k8s.Backend {
	be := &k8s.Backend{Ports: map[loadbalancer.L4Addr][]string{}}
	for _, port := range ports {
		be.Ports[loadbalancer.L4Addr{Protocol: loadbalancer.TCP, Port: port}] = nil
	}
	return be
}

func l3n4AddrFor(ip cmtypes.AddrCluster, port uint16) loadbalancer.L3n4Addr {
	return loadbalancer.NewL3n4Addr(
		loadbalancer.TCP,
		ip,
		port,
		loadbalancer.ScopeExternal,
	)
}

func newCache(eps ...Endpoints) Cache {
	var cache Cache
	for _, ep := range eps {
		cache.Update(ep)
	}
	return cache
}

func collectOrphans(cache Cache, eps ...Endpoints) []loadbalancer.L3n4Addr {
	var out []loadbalancer.L3n4Addr
	for addr := range cache.Orphans(slices.Values(eps)) {
		out = append(out, addr)
	}
	return out
}

func TestOrphans(t *testing.T) {
	svc := loadbalancer.NewServiceName("default", "test")
	newSlice := func(name string, backends map[cmtypes.AddrCluster]*k8s.Backend) Endpoints {
		return Endpoints{
			Name:        "default/" + name,
			ServiceName: svc,
			Backends:    backends,
		}
	}
	ip1 := cmtypes.MustParseAddrCluster("10.0.0.1")
	ip2 := cmtypes.MustParseAddrCluster("10.0.0.2")

	t.Run("deleting one of two slices sharing a backend orphans nothing", func(t *testing.T) {
		cache := newCache(
			newSlice("slice-1", map[cmtypes.AddrCluster]*k8s.Backend{ip1: backendWithPorts(80)}),
			newSlice("slice-2", map[cmtypes.AddrCluster]*k8s.Backend{ip1: backendWithPorts(80)}),
		)
		// slice-1 is deleted (passed with nil backends); slice-2 is unchanged
		// and not part of this batch.
		orphans := collectOrphans(cache, newSlice("slice-1", nil))
		require.Empty(t, orphans)
	})

	t.Run("unique backend of deleted slice is orphaned", func(t *testing.T) {
		cache := newCache(
			newSlice("slice-1", map[cmtypes.AddrCluster]*k8s.Backend{
				ip1: backendWithPorts(80),
				ip2: backendWithPorts(80),
			}),
			newSlice("slice-2", map[cmtypes.AddrCluster]*k8s.Backend{ip1: backendWithPorts(80)}),
		)
		orphans := collectOrphans(cache, newSlice("slice-1", nil))
		require.Equal(t, []loadbalancer.L3n4Addr{l3n4AddrFor(ip2, 80)}, orphans)
	})

	t.Run("backend removed from the only slice is orphaned", func(t *testing.T) {
		cache := newCache(
			newSlice("slice-1", map[cmtypes.AddrCluster]*k8s.Backend{ip1: backendWithPorts(80)}),
		)
		orphans := collectOrphans(cache, newSlice("slice-1", nil))
		require.Equal(t, []loadbalancer.L3n4Addr{l3n4AddrFor(ip1, 80)}, orphans)
	})

	t.Run("port dropped from one slice but kept on another is not orphaned", func(t *testing.T) {
		cache := newCache(
			newSlice("slice-1", map[cmtypes.AddrCluster]*k8s.Backend{ip1: backendWithPorts(80, 443)}),
			newSlice("slice-2", map[cmtypes.AddrCluster]*k8s.Backend{ip1: backendWithPorts(443)}),
		)
		// slice-1 is updated to drop :443; :443 remains on slice-2.
		orphans := collectOrphans(cache,
			newSlice("slice-1", map[cmtypes.AddrCluster]*k8s.Backend{ip1: backendWithPorts(80)}))
		require.Empty(t, orphans)
	})

	t.Run("backends of other services are never orphaned", func(t *testing.T) {
		other := loadbalancer.NewServiceName("default", "other")
		cache := newCache(
			newSlice("slice-1", map[cmtypes.AddrCluster]*k8s.Backend{ip1: backendWithPorts(80)}),
			Endpoints{
				Name:        "default/slice-9",
				ServiceName: other,
				Backends:    map[cmtypes.AddrCluster]*k8s.Backend{ip1: backendWithPorts(80)},
			},
		)
		orphans := collectOrphans(cache, newSlice("slice-1", nil))
		require.Equal(t, []loadbalancer.L3n4Addr{l3n4AddrFor(ip1, 80)}, orphans)
	})

	t.Run("orphans only scans slices of the affected service", func(t *testing.T) {
		other := loadbalancer.NewServiceName("default", "other")
		cache := newCache(
			newSlice("slice-1", map[cmtypes.AddrCluster]*k8s.Backend{ip1: backendWithPorts(80)}),
			Endpoints{
				Name:        "default/slice-9",
				ServiceName: other,
				Backends:    map[cmtypes.AddrCluster]*k8s.Backend{ip2: backendWithPorts(80)},
			},
		)
		// The other service's slice holds a backend that must not be yielded
		// nor counted as present when computing orphans for svc.
		orphans := collectOrphans(cache, newSlice("slice-1", nil))
		require.Equal(t, []loadbalancer.L3n4Addr{l3n4AddrFor(ip1, 80)}, orphans)

		// Deleting a slice of the other service only orphans its own backend.
		orphans = collectOrphans(cache, Endpoints{
			Name:        "default/slice-9",
			ServiceName: other,
		})
		require.Equal(t, []loadbalancer.L3n4Addr{l3n4AddrFor(ip2, 80)}, orphans)
	})

	t.Run("update keeps the service index consistent", func(t *testing.T) {
		var cache Cache
		require.True(t, cache.IsEmpty())

		cache.Update(newSlice("slice-1", map[cmtypes.AddrCluster]*k8s.Backend{ip1: backendWithPorts(80)}))
		require.False(t, cache.IsEmpty())
		require.Len(t, cache.byService[svc], 1)

		// Deleting the slice removes it from both indexes.
		cache.Update(newSlice("slice-1", nil))
		require.True(t, cache.IsEmpty())
		require.NotContains(t, cache.byService, svc)

		// Clearing drops everything.
		cache.Update(newSlice("slice-1", map[cmtypes.AddrCluster]*k8s.Backend{ip1: backendWithPorts(80)}))
		cache.Clear()
		require.True(t, cache.IsEmpty())
	})
}
