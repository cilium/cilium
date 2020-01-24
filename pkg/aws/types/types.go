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

package types

import (
	"github.com/cilium/cilium/pkg/ipam"
	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
)

// SecurityGroup is the representation of an AWS Security Group
type SecurityGroup struct {
	// ID is the SecurityGroup ID
	ID string

	// VpcID is the VPC ID in which the security group resides
	VpcID string

	// Tags are the tags of the security group
	Tags ipam.Tags
}

// instance is the minimal representation of an AWS instance as needed by the
// ENI allocator
type instance struct {
	// enis is a map of all ENIs attached to the instance indexed by the
	// ENI ID
	enis map[string]*v2.ENI
}

// InstanceMap is the list of all instances indexed by instance ID
type InstanceMap map[string]*instance

// Add adds an instance definition to the instance map. instanceMap may not be
// subject to concurrent access while add() is used.
func (m InstanceMap) Add(instanceID string, eni *v2.ENI) {
	i, ok := m[instanceID]
	if !ok {
		i = &instance{}
		m[instanceID] = i
	}

	if i.enis == nil {
		i.enis = map[string]*v2.ENI{}
	}

	i.enis[eni.ID] = eni
}

// Update updates the ENI definition of an ENI for a particular instance. If
// the ENI is already known, the definition is updated, otherwise the ENI is
// added to the instance.
func (m InstanceMap) Update(instanceID string, eni *v2.ENI) {
	if i, ok := m[instanceID]; ok {
		i.enis[eni.ID] = eni
	} else {
		m.Add(instanceID, eni)
	}
}

// Get returns the list of ENIs for a particular instance ID
func (m InstanceMap) Get(instanceID string) (enis []*v2.ENI) {
	if instance, ok := m[instanceID]; ok {
		for _, e := range instance.enis {
			enis = append(enis, e.DeepCopy())
		}
	}

	return
}

// SecurityGroupMap indexes AWS Security Groups by security group ID
type SecurityGroupMap map[string]*SecurityGroup
