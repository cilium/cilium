// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package metadata

import (
	"errors"
	"testing"

	"k8s.io/client-go/tools/cache"

	"github.com/cilium/cilium/pkg/annotation"
	ipamOption "github.com/cilium/cilium/pkg/ipam/option"
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

func (m mockStore[T]) CacheStore() cache.Store {
	panic("not implemented")
}

func podKey(ns, name string) resource.Key {
	return resource.Key{
		Namespace: ns,
		Name:      name,
	}
}

func namespaceKey(name string) resource.Key {
	return resource.Key{
		Name: name,
	}
}

func TestManager_GetIPPoolForPod(t *testing.T) {
	m := &Manager{
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
		podStore: mockStore[*slim_core_v1.Pod]{
			podKey("default", "client"): &slim_core_v1.Pod{},
			podKey("default", "custom-workload"): &slim_core_v1.Pod{
				ObjectMeta: slim_meta_v1.ObjectMeta{
					Annotations: map[string]string{
						annotation.IPAMPoolKey: "custom-pool",
					},
				},
			},

			podKey("special", "server"): &slim_core_v1.Pod{},
			podKey("special", "server2"): &slim_core_v1.Pod{
				ObjectMeta: slim_meta_v1.ObjectMeta{
					Annotations: map[string]string{
						annotation.IPAMPoolKey: "pod-pool",
					},
				},
			},

			podKey("missing-ns", "pod"): &slim_core_v1.Pod{},
		},
	}

	tests := []struct {
		name     string
		owner    string
		wantPool string
		wantErr  error
	}{
		{
			name:     "no annotations",
			owner:    "default/client",
			wantPool: ipamOption.PoolDefault,
		},
		{
			name:     "not a pod name",
			owner:    "router",
			wantPool: ipamOption.PoolDefault,
		},
		{
			name:     "also not a pod name (due to underline)",
			owner:    "default/xwing_net2",
			wantPool: ipamOption.PoolDefault,
		},
		{
			name:     "pod annotation",
			owner:    "default/custom-workload",
			wantPool: "custom-pool",
		},
		{
			name:     "namespace annotation",
			owner:    "special/server",
			wantPool: "namespace-pool",
		},
		{
			name:     "pod annotation in namespace with annotation",
			owner:    "special/server2",
			wantPool: "pod-pool",
		},
		{
			name:    "missing pod",
			owner:   "does-not/exist",
			wantErr: &ResourceNotFound{Resource: "Pod"},
		},
		{
			name:    "missing namespace",
			owner:   "missing-ns/pod",
			wantErr: &ResourceNotFound{Resource: "Namespace"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotPool, err := m.GetIPPoolForPod(tt.owner)
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
