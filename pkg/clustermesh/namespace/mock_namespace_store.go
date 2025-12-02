// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package namespace

import (
	"log/slog"

	"k8s.io/client-go/tools/cache"

	"github.com/cilium/cilium/pkg/k8s/resource"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
)

// MockNamespaceStore is a mock implementation of resource.Store for testing
type MockNamespaceStore struct {
	namespaces map[string]*slim_corev1.Namespace
}

func NewMockNamespaceStore(namespaces ...*slim_corev1.Namespace) *MockNamespaceStore {
	store := &MockNamespaceStore{
		namespaces: make(map[string]*slim_corev1.Namespace),
	}
	for _, ns := range namespaces {
		store.namespaces[ns.Name] = ns
	}
	return store
}

func (m *MockNamespaceStore) GetByKey(key resource.Key) (*slim_corev1.Namespace, bool, error) {
	ns, exists := m.namespaces[key.Name]
	return ns, exists, nil
}

func (m *MockNamespaceStore) Get(obj *slim_corev1.Namespace) (*slim_corev1.Namespace, bool, error) {
	return m.GetByKey(resource.Key{Name: obj.Name})
}

func (m *MockNamespaceStore) List() []*slim_corev1.Namespace {
	var result []*slim_corev1.Namespace
	for _, ns := range m.namespaces {
		result = append(result, ns)
	}
	return result
}

func (m *MockNamespaceStore) IterKeys() resource.KeyIter {
	return &mockKeyIterator{}
}

func (m *MockNamespaceStore) IndexKeys(indexName, indexedValue string) ([]string, error) {
	return nil, nil
}

func (m *MockNamespaceStore) ByIndex(indexName, indexedValue string) ([]*slim_corev1.Namespace, error) {
	return nil, nil
}

func (m *MockNamespaceStore) CacheStore() cache.Store {
	return nil
}

type mockKeyIterator struct{}

func (m *mockKeyIterator) Next() bool        { return false }
func (m *mockKeyIterator) Key() resource.Key { return resource.Key{} }

// NewMockNamespaceManager creates a mock Namespace Manager with the provided namespaces.
func NewMockNamespaceManager(enableDefaultGlobalNamespace bool, namespaces ...*slim_corev1.Namespace) Manager {
	return &manager{
		store: &MockNamespaceStore{
			namespaces: func() map[string]*slim_corev1.Namespace {
				nsMap := make(map[string]*slim_corev1.Namespace)
				for _, ns := range namespaces {
					nsMap[ns.Name] = ns
				}
				return nsMap
			}(),
		},
		cfg: Config{
			EnableDefaultGlobalNamespace: enableDefaultGlobalNamespace,
		},
		logger: slog.Default(),
	}
}
