// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package observer

import (
	"context"
	"sort"

	observerpb "github.com/cilium/cilium/api/v1/observer"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/time"
)

var _ NamespaceManager = &namespaceManager{}

const (
	checkNamespaceAgeFrequency = 5 * time.Minute
	namespaceTTL               = time.Hour
)

type NamespaceManager interface {
	GetNamespaces() []*observerpb.Namespace
	AddNamespace(*observerpb.Namespace)
}

type namespaceRecord struct {
	namespace *observerpb.Namespace
	added     time.Time
}

type namespaceManager struct {
	mu         lock.RWMutex
	namespaces map[string]namespaceRecord
	nowFunc    func() time.Time
}

func NewNamespaceManager() *namespaceManager {
	return &namespaceManager{
		namespaces: make(map[string]namespaceRecord),
		nowFunc:    time.Now,
	}
}

func (m *namespaceManager) Run(ctx context.Context) {
	ticker := time.NewTicker(checkNamespaceAgeFrequency)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			// periodically remove any namespaces which haven't been seen in flows
			// for the last hour
			m.cleanupNamespaces()
		}
	}
}

func (m *namespaceManager) cleanupNamespaces() {
	m.mu.Lock()
	for key, record := range m.namespaces {
		if record.added.Add(namespaceTTL).Before(m.nowFunc()) {
			delete(m.namespaces, key)
		}
	}
	m.mu.Unlock()
}

func (m *namespaceManager) GetNamespaces() []*observerpb.Namespace {
	m.mu.RLock()
	namespaces := make([]*observerpb.Namespace, 0, len(m.namespaces))
	for _, ns := range m.namespaces {
		namespaces = append(namespaces, ns.namespace)
	}
	m.mu.RUnlock()

	sort.Slice(namespaces, func(i, j int) bool {
		a := namespaces[i]
		b := namespaces[j]
		if a.Cluster != b.Cluster {
			return a.Cluster < b.Cluster
		}
		return a.Namespace < b.Namespace
	})
	return namespaces
}

func (m *namespaceManager) AddNamespace(ns *observerpb.Namespace) {
	m.mu.Lock()
	defer m.mu.Unlock()

	key := ns.GetCluster() + "/" + ns.GetNamespace()
	m.namespaces[key] = namespaceRecord{namespace: ns, added: m.nowFunc()}
}
