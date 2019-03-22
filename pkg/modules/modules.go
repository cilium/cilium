// Copyright 2019 Authors of Cilium
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

package modules

import (
	"github.com/cilium/cilium/pkg/set"
)

// ModuleInfo is a struct representing information about kernel module.
type ModuleInfo struct {
	Name         string
	Dependencies []string
}

// ModulesManager is a manager which stores information about loaded modules
// and provides a search operation.
type ModulesManager struct {
	modulesMap []*ModuleInfo
}

func (m *ModulesManager) Init() error {
	modulesMap, err := listModules()
	if err != nil {
		return err
	}
	m.modulesMap = modulesMap
	return nil
}

func (m *ModulesManager) FindModule(expectedName string, expectedDeps ...string) bool {
	for _, modInfo := range m.modulesMap {
		if modInfo.Name == expectedName && set.Subset(expectedDeps, modInfo.Dependencies) {
			return true
		}
	}
	return false
}
