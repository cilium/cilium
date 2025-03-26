// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ebpf

import (
	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

var (
	mutex       lock.RWMutex
	mapRegister = map[string]*Map{}
)

func registerMap(m *Map) {
	mutex.Lock()
	mapRegister[m.path] = m
	mutex.Unlock()

	m.logger.Debug("Registered BPF map", logfields.Path, m.path)
}

// GetOpenMaps returns a slice of all open BPF maps. This is identical to
// calling GetMap() on all open maps.
func GetOpenMaps() []*models.BPFMap {
	// create a copy of mapRegister so we can unlock the mutex again as
	// locking Map.lock inside of the mutex is not permitted
	mutex.RLock()
	maps := make([]*Map, 0, len(mapRegister))
	for _, m := range mapRegister {
		maps = append(maps, m)
	}
	mutex.RUnlock()

	mapList := make([]*models.BPFMap, len(maps))
	for i, m := range maps {
		mapList[i] = m.GetModel()
	}

	return mapList
}
