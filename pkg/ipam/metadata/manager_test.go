// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package metadata

import (
	"errors"
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/cilium/statedb"
	"github.com/stretchr/testify/require"
	"k8s.io/client-go/tools/cache"

	"github.com/cilium/cilium/daemon/k8s"
	"github.com/cilium/cilium/pkg/annotation"
	"github.com/cilium/cilium/pkg/ipam"
	"github.com/cilium/cilium/pkg/k8s/resource"
	slim_core_v1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	slim_meta_v1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
)

type mockStore[T comparable] map[resource.Key]T

func (m mockStore[T]) GetByKey(key resource.Key) (item T, exists bool, err error) {
	item, exists = m[key]
	return item, exists, nil
}

func (m mockStore[T]) Get(obj T) (item T, exists bool, err error) {
	panic("not implemented")
}

func (m mockStore[T]) List() []T {
	panic("not implemented")
}

func (m mockStore[T]) IterKeys() resource.KeyIter {
	panic("not implemented")
}

func (m mockStore[T]) IndexKeys(indexName, indexedValue string) ([]string, error) {
	panic("not implemented")
}

func (m mockStore[T]) ByIndex(indexName, indexedValue string) ([]T, error) {
	panic("not implemented")
}

func (m mockStore[T]) CacheStore() cache.Store {
	panic("not implemented")
}

func namespaceKey(name string) resource.Key {
	return resource.Key{
		Name: name,
	}
}

func TestManager_GetIPPoolForPod(t *testing.T) {
	db := statedb.New()
	pods, err := k8s.NewPodTable(db)
	require.NoError(t, err, "NewPodTable")
	m := &manager{
		logger: hivetest.Logger(t),
		db:     db,
		namespaceStore: mockStore[*slim_core_v1.Namespace]{
			namespaceKey("default"): &slim_core_v1.Namespace{},
			namespaceKey("special"): &slim_core_v1.Namespace{
				ObjectMeta: slim_meta_v1.ObjectMeta{
					Annotations: map[string]string{
						annotation.IPAMPoolKey: "namespace-pool",
					},
				},
			},
		},
		pods: pods,
	}

	txn := db.WriteTxn(pods)
	newPod := func(namespace, name string, annotations map[string]string) k8s.LocalPod {
		return k8s.LocalPod{Pod: &slim_core_v1.Pod{
			ObjectMeta: slim_meta_v1.ObjectMeta{
				Namespace:   namespace,
				Name:        name,
				Annotations: annotations,
			},
		}}
	}
	pods.Insert(txn, newPod("default", "client", nil))
	pods.Insert(txn, newPod("default", "custom-workload",
		map[string]string{
			annotation.IPAMPoolKey: "custom-pool",
		}))
	pods.Insert(txn, newPod("default", "custom-workload2",
		map[string]string{
			annotation.IPAMIPv4PoolKey: "ipv4-pool",
		}))
	pods.Insert(txn, newPod("default", "custom-workload3",
		map[string]string{
			annotation.IPAMIPv4PoolKey: "ipv4-pool",
			annotation.IPAMPoolKey:     "custom-pool",
		}))
	pods.Insert(txn, newPod("default", "custom-workload4",
		map[string]string{
			annotation.IPAMIPv4PoolKey: "ipv4-pool",
			annotation.IPAMIPv6PoolKey: "ipv6-pool",
		}))
	pods.Insert(txn, newPod("default", "custom-workload5",
		map[string]string{
			annotation.IPAMIPv4PoolKey: "ipv4-pool",
			annotation.IPAMIPv6PoolKey: "ipv6-pool",
			annotation.IPAMPoolKey:     "custom-pool",
		}))

	pods.Insert(txn, newPod("special", "server", nil))
	pods.Insert(txn, newPod("special", "server2",
		map[string]string{
			annotation.IPAMPoolKey: "pod-pool",
		}))
	pods.Insert(txn, newPod("missing-ns", "pod", nil))
	txn.Commit()

	tests := []struct {
		name     string
		owner    string
		ipfamily ipam.Family
		wantPool string
		wantErr  error
	}{
		{
			name:     "no annotations",
			owner:    "default/client",
			ipfamily: ipam.IPv4,
			wantPool: ipam.PoolDefault().String(),
		},
		{
			name:     "not a pod name",
			owner:    "router",
			ipfamily: ipam.IPv4,
			wantPool: ipam.PoolDefault().String(),
		},
		{
			name:     "also not a pod name (due to underline)",
			owner:    "default/xwing_net2",
			ipfamily: ipam.IPv4,
			wantPool: ipam.PoolDefault().String(),
		},
		{
			name:     "pod annotation",
			owner:    "default/custom-workload",
			ipfamily: ipam.IPv4,
			wantPool: "custom-pool",
		},
		{
			name:     "pod annotation only ipv4 pool request ipv4",
			owner:    "default/custom-workload2",
			ipfamily: ipam.IPv4,
			wantPool: "ipv4-pool",
		},
		{
			name:     "pod annotation only ipv4 pool request ipv6",
			owner:    "default/custom-workload2",
			ipfamily: ipam.IPv6,
			wantPool: ipam.PoolDefault().String(),
		},
		{
			name:     "pod annotation ipv4 and custom pool request ipv4",
			owner:    "default/custom-workload3",
			ipfamily: ipam.IPv4,
			wantPool: "ipv4-pool",
		},
		{
			name:     "pod annotation ipv4 and custom pool request ipv6",
			owner:    "default/custom-workload3",
			ipfamily: ipam.IPv6,
			wantPool: "custom-pool",
		},
		{
			name:     "pod annotation ipv4 and ipv6 pool request ipv4",
			owner:    "default/custom-workload4",
			ipfamily: ipam.IPv4,
			wantPool: "ipv4-pool",
		},
		{
			name:     "pod annotation ipv4 and ipv6 pool request ipv6",
			owner:    "default/custom-workload4",
			ipfamily: ipam.IPv6,
			wantPool: "ipv6-pool",
		},
		{
			name:     "pod annotation ipv4, ipv6 and custom pool request ipv4",
			owner:    "default/custom-workload3",
			ipfamily: ipam.IPv4,
			wantPool: "ipv4-pool",
		},
		{
			name:     "pod annotation ipv4, ipv6 and custom pool request ipv6",
			owner:    "default/custom-workload5",
			ipfamily: ipam.IPv6,
			wantPool: "ipv6-pool",
		},
		{
			name:     "missing pod",
			owner:    "does-not/exist",
			ipfamily: ipam.IPv4,
			wantErr:  &ResourceNotFound{Resource: "Pod"},
		},
		{
			name:     "missing namespace",
			owner:    "missing-ns/pod",
			ipfamily: ipam.IPv4,
			wantErr:  &ResourceNotFound{Resource: "Namespace"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotPool, err := m.GetIPPoolForPod(tt.owner, tt.ipfamily)
			if !errors.Is(err, tt.wantErr) {
				t.Errorf("GetIPPoolForPod() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if gotPool != tt.wantPool {
				t.Errorf("GetIPPoolForPod() gotPool = %v, want %v", gotPool, tt.wantPool)
			}
		})
	}
}

func TestDefaultManager_DefaultPool(t *testing.T) {
	defaultPoolManager := defaultIPPoolManager{}

	ipv4Pool, err := defaultPoolManager.GetIPPoolForPod("", ipam.IPv4)
	require.NoError(t, err)
	require.Equal(t, ipam.PoolDefault(), ipam.Pool(ipv4Pool))

	ipv6Pool, err := defaultPoolManager.GetIPPoolForPod("", ipam.IPv6)
	require.NoError(t, err)
	require.Equal(t, ipam.PoolDefault(), ipam.Pool(ipv6Pool))
}
