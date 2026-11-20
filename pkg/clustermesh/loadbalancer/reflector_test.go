// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package loadbalancer

import (
	"slices"
	"testing"

	"github.com/stretchr/testify/require"

	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/k8s"
	"github.com/cilium/cilium/pkg/loadbalancer"
	reflectorEndpoints "github.com/cilium/cilium/pkg/loadbalancer/reflectors/endpoints"
)

func clusterBackendWithPorts(ports ...uint16) *k8s.Backend {
	be := &k8s.Backend{Ports: map[loadbalancer.L4Addr][]string{}}
	for _, port := range ports {
		be.Ports[loadbalancer.L4Addr{Protocol: loadbalancer.TCP, Port: port}] = nil
	}
	return be
}

func clusterTestEndpoints(svc loadbalancer.ServiceName, sliceName string, deleted bool, backends map[cmtypes.AddrCluster]*k8s.Backend) *k8s.Endpoints {
	ep := &k8s.Endpoints{
		EndpointSliceID: k8s.EndpointSliceID{
			ServiceName:       svc,
			EndpointSliceName: sliceName,
		},
	}
	if !deleted {
		ep.Backends = backends
	}
	return ep
}

func clusterL3n4Addr(ip cmtypes.AddrCluster, port uint16) loadbalancer.L3n4Addr {
	return loadbalancer.NewL3n4Addr(loadbalancer.TCP, ip, port, loadbalancer.ScopeExternal)
}

// processBatch feeds one buffered event batch for a cluster through the
// reflector's cache bookkeeping and returns the orphaned backend addresses.
func processBatch(caches map[uint32]reflectorEndpoints.Cache, clusterID uint32, svc loadbalancer.ServiceName, sliceName string, deleted bool, backends map[cmtypes.AddrCluster]*k8s.Backend) []loadbalancer.L3n4Addr {
	var allEps reflectorEndpoints.AllEndpoints
	allEps = allEps.Insert(deleted, clusterTestEndpoints(svc, sliceName, deleted, backends))
	return slices.Collect(updateClusterCache(caches, clusterID, allEps))
}

// TestUpdateClusterCacheUpsertThenDelete is a regression test for the
// ClusterMesh reflector losing the per-cluster endpoint cache between events:
// Cache is a struct, so the copy updated by UpdateMany must be stored back
// into the map. Without the store-back the next event saw an empty cache and
// deleted remote backends were never released.
func TestUpdateClusterCacheUpsertThenDelete(t *testing.T) {
	svc := loadbalancer.NewServiceName("default", "test")
	ip1 := cmtypes.MustParseAddrCluster("10.0.0.1")

	t.Run("deleted backend is released and empty cluster entry is dropped", func(t *testing.T) {
		caches := map[uint32]reflectorEndpoints.Cache{}

		orphans := processBatch(caches, 1, svc, "default/slice-1", false,
			map[cmtypes.AddrCluster]*k8s.Backend{ip1: clusterBackendWithPorts(80)})
		require.Empty(t, orphans)
		require.Contains(t, caches, uint32(1), "updated cache must be stored back")

		orphans = processBatch(caches, 1, svc, "default/slice-1", true, nil)
		require.Equal(t, []loadbalancer.L3n4Addr{clusterL3n4Addr(ip1, 80)}, orphans)
		require.NotContains(t, caches, uint32(1), "empty cluster entry must be dropped")
	})

	t.Run("deleting one of two slices orphans nothing and keeps the entry", func(t *testing.T) {
		caches := map[uint32]reflectorEndpoints.Cache{}

		orphans := processBatch(caches, 1, svc, "default/slice-1", false,
			map[cmtypes.AddrCluster]*k8s.Backend{ip1: clusterBackendWithPorts(80)})
		require.Empty(t, orphans)

		orphans = processBatch(caches, 1, svc, "default/slice-2", false,
			map[cmtypes.AddrCluster]*k8s.Backend{ip1: clusterBackendWithPorts(80)})
		require.Empty(t, orphans)

		// Deleting slice-1 must not orphan the backend still referenced by
		// slice-2, and the cluster entry must be retained.
		orphans = processBatch(caches, 1, svc, "default/slice-1", true, nil)
		require.Empty(t, orphans)
		require.Contains(t, caches, uint32(1))
	})
}
