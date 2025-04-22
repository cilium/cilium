// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package common

import (
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"

	serviceStore "github.com/cilium/cilium/pkg/clustermesh/store"
	"github.com/cilium/cilium/pkg/metrics"
)

type fakeUpstream struct {
	updated map[string]int
	deleted map[string]int
}

func (f *fakeUpstream) init() {
	f.updated = make(map[string]int)
	f.deleted = make(map[string]int)
}

func (f *fakeUpstream) OnUpdate(service *serviceStore.ClusterService) { f.updated[service.String()]++ }
func (f *fakeUpstream) OnDelete(service *serviceStore.ClusterService) { f.deleted[service.String()]++ }

func TestRemoteServiceObserver(t *testing.T) {
	wrap := func(svc serviceStore.ClusterService) *serviceStore.ValidatingClusterService {
		return &serviceStore.ValidatingClusterService{ClusterService: svc}
	}
	svc1 := serviceStore.ClusterService{Cluster: "remote", Namespace: "namespace", Name: "name", IncludeExternal: false, Shared: true}
	svc2 := serviceStore.ClusterService{Cluster: "remote", Namespace: "namespace", Name: "name"}
	cache := NewGlobalServiceCache(hivetest.Logger(t), metrics.NoOpGauge)

	var upstream fakeUpstream
	observer := NewSharedServicesObserver(hivetest.Logger(t), cache, upstream.OnUpdate, upstream.OnDelete)

	// Observe a new service update (for a non-shared service), and assert it is not added to the cache
	upstream.init()
	observer.OnUpdate(wrap(svc2))

	require.Equal(t, 0, upstream.updated[svc1.String()])
	require.Equal(t, 0, cache.Size())

	// Observe a new service update (for a shared service), and assert it is correctly added to the cache
	upstream.init()
	observer.OnUpdate(wrap(svc1))

	require.Equal(t, 1, upstream.updated[svc1.String()])
	require.Equal(t, 0, upstream.deleted[svc1.String()])
	require.Equal(t, 1, cache.Size())

	gs := cache.GetGlobalService(svc1.NamespaceServiceName())
	require.Len(t, gs.ClusterServices, 1)
	found, ok := gs.ClusterServices[svc1.Cluster]
	require.True(t, ok)
	require.Equal(t, &svc1, found)

	// Observe a new service deletion, and assert it is correctly removed from the cache
	upstream.init()
	observer.OnDelete(wrap(svc1))

	require.Equal(t, 0, upstream.updated[svc1.String()])
	require.Equal(t, 1, upstream.deleted[svc1.String()])
	require.Equal(t, 0, cache.Size())

	// Observe two service updates in sequence (first shared, then non-shared),
	// and assert that at the end it is not present in the cache (equivalent to update, then delete).
	upstream.init()
	observer.OnUpdate(wrap(svc1))
	observer.OnUpdate(wrap(svc2))

	require.Equal(t, 1, upstream.updated[svc1.String()])
	require.Equal(t, 1, upstream.deleted[svc1.String()])
	require.Equal(t, 0, cache.Size())
}
