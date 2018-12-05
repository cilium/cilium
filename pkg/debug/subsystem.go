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

package debug

import (
	"fmt"

	"github.com/cilium/cilium/pkg/lock"
)

// StatusFunc is a function returning the debug status of a subsytem. It is
// passed into RegisterStatusFunc().
type StatusFunc func() string

// StatusMap is the collection of debug status of all subsystems. The key is
// the subsystem name. The value is the subsystem debug status.
type StatusMap map[string]string

// StatusObject is the interface an object must impelement to be able to be
// passed into RegisterStatusObject().
type StatusObject interface {
	// DebugStatus() is the equivalent of StatusFunc. It must return the
	// debug status as a string.
	DebugStatus() string
}

type functionMap map[string]StatusFunc

type statusFunctions struct {
	functions functionMap
	mutex     lock.RWMutex
}

func newStatusFunctions() statusFunctions {
	return statusFunctions{
		functions: functionMap{},
	}
}

func (s *statusFunctions) register(name string, fn StatusFunc) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	if _, ok := s.functions[name]; ok {
		return fmt.Errorf("subsystem already registered")
	}

	s.functions[name] = fn

	return nil
}

func (s *statusFunctions) registerStatusObject(name string, obj StatusObject) error {
	return s.register(name, func() string { return obj.DebugStatus() })
}

func (s *statusFunctions) collectStatus() StatusMap {
	fnCopy := functionMap{}

	// Make a copy to not hold the mutex while collecting the status
	s.mutex.RLock()
	for name, fn := range s.functions {
		fnCopy[name] = fn
	}
	s.mutex.RUnlock()

	status := StatusMap{}

	for name, fn := range fnCopy {
		status[name] = fn()
	}

	return status
}

var globalStatusFunctions = newStatusFunctions()

// RegisterStatusFunc registers a subsystem and associates a status function to
// call for debug status collection
func RegisterStatusFunc(name string, fn StatusFunc) error {
	return globalStatusFunctions.register(name, fn)
}

// RegisterStatusObject registers a subsystem and associated a status object on
// which DebugStatus() is called to collect debug status
func RegisterStatusObject(name string, obj StatusObject) error {
	return globalStatusFunctions.registerStatusObject(name, obj)
}

// CollectSubsystemStatus collects the status of all subsystems and returns it
func CollectSubsystemStatus() StatusMap {
	return globalStatusFunctions.collectStatus()
}
