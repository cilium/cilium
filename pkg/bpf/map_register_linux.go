// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build linux

package bpf

import (
	"log/slog"
	"path"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

var (
	mutex       lock.RWMutex
	mapRegister = map[string]*Map{}
)

func registerMap(logger *slog.Logger, path string, m *Map) {
	mutex.Lock()
	mapRegister[path] = m
	mutex.Unlock()

	logger.Debug("Registered BPF map", logfields.Path, path)
}

func unregisterMap(logger *slog.Logger, path string, m *Map) {
	mutex.Lock()
	delete(mapRegister, path)
	mutex.Unlock()

	logger.Debug("Unregistered BPF map", logfields.Path, path)
}

// GetMap returns the registered map with the given name or absolute path
func GetMap(logger *slog.Logger, name string) *Map {
	mutex.RLock()
	defer mutex.RUnlock()

	if !path.IsAbs(name) {
		name = MapPath(logger, name)
	}

	return mapRegister[name]
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

	i := 0
	for _, m := range maps {
		mapList[i] = m.GetModel()
		i++
	}

	return mapList
}
