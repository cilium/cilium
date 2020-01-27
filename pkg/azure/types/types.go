// Copyright 2020 Authors of Cilium
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

package types

import (
	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
)

// instance is the minimal representation of a Azure instance as needed by the
// IPAM plugin
type instance struct {
	// interfaces is a map of all interfaces attached to the instance
	// indexed by the ID
	interfaces map[string]*v2.AzureInterface
}

// InstanceMap is the list of all instances indexed by instance ID
type InstanceMap map[string]*instance

// Update updates the definition of an Azure interface for a particular
// instance. If the interface is already known, the definition is updated,
// otherwise the interface is added to the instance.
func (m InstanceMap) Update(instanceID string, iface *v2.AzureInterface) {
	i, ok := m[instanceID]
	if !ok {
		i = &instance{}
		m[instanceID] = i
	}

	if i.interfaces == nil {
		i.interfaces = map[string]*v2.AzureInterface{}
	}

	i.interfaces[iface.ID] = iface
}

// Get returns the list of interfaces for a particular instance ID. The
// returned interfaces are deep copied and can be safely accessed but will
// become stale.
func (m InstanceMap) Get(instanceID string) (interfaces []*v2.AzureInterface) {
	if instance, ok := m[instanceID]; ok {
		for _, iface := range instance.interfaces {
			interfaces = append(interfaces, iface.DeepCopy())
		}
	}

	return
}
