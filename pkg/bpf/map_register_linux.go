// Copyright 2018 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// +build linux

package bpf

import (
	"path"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/lock"
)

var (
	mutex       lock.RWMutex
	mapRegister = map[string]*Map{}
)

func registerMap(path string, m *Map) {
	mutex.Lock()
	mapRegister[path] = m
	mutex.Unlock()

	log.WithField("path", path).Debug("Registered BPF map")
}

func unregisterMap(path string, m *Map) {
	mutex.Lock()
	delete(mapRegister, path)
	mutex.Unlock()

	log.WithField("path", path).Debug("Unregistered BPF map")
}

// GetMap returns the registered map with the given name or absolute path
func GetMap(name string) *Map {
	mutex.RLock()
	defer mutex.RUnlock()

	if !path.IsAbs(name) {
		name = MapPath(name)
	}

	return mapRegister[name]
}

// GetOpenMaps returns a slice of all open BPF maps. This is identical to
// calling GetMap() on all open maps.
func GetOpenMaps() []*models.BPFMap {
	// create a copy of mapRegister so we can unlock the mutex again as
	// locking Map.lock inside of the mutex is not permitted
	mutex.RLock()
	maps := []*Map{}
	for _, m := range mapRegister {
		maps = append(maps, m)
	}
	mutex.RUnlock()

	mapList := make([]*models.BPFMap, len(maps))

	i := 0
	for _, m := range maps {
		mapList[i] = m.GetModel()
		i++
	}

	return mapList
}
