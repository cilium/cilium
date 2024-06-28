// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package synced

import (
	"github.com/cilium/cilium/pkg/lock"
)

// APIGroups is a lockable map to hold which k8s API Groups we have
// enabled/in-use
// Note: We can replace it with a Go 1.9 map once we require that version
type APIGroups struct {
	lock.RWMutex
	apis map[string]bool
}

func (m *APIGroups) AddAPI(api string) {
	m.Lock()
	defer m.Unlock()
	if m.apis == nil {
		m.apis = make(map[string]bool)
	}
	m.apis[api] = true
}

func (m *APIGroups) RemoveAPI(api string) {
	m.Lock()
	defer m.Unlock()
	delete(m.apis, api)
}

func (m *APIGroups) GetGroups() []string {
	m.RLock()
	defer m.RUnlock()
	groups := make([]string, 0, len(m.apis))
	for k := range m.apis {
		groups = append(groups, k)
	}
	return groups
}
