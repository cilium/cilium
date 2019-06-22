// Copyright 2019 Authors of Cilium
// Copyright 2017 Lyft, Inc.
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

package eni

import (
	"github.com/cilium/cilium/pkg/aws/types"
	"github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/lock"

	"github.com/sirupsen/logrus"
)

type instanceAPI interface {
	GetInstances(vpcs VpcMap, subnets SubnetMap) (InstanceMap, error)
	GetSubnets() (SubnetMap, error)
	GetVpcs() (VpcMap, error)
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

// SubnetMap indexes AWS subnets by subnet ID
type SubnetMap map[string]*types.Subnet

// VpcMap indexes AWS VPCs by VPC ID
type VpcMap map[string]*types.Vpc

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

// InstancesManager maintains the list of instances. It must be kept up to date
// by calling resync() regularly.
type InstancesManager struct {
	mutex      lock.RWMutex
	instances  InstanceMap
	subnets    SubnetMap
	vpcs       VpcMap
	api        instanceAPI
	metricsAPI metricsAPI
}

// NewInstancesManager returns a new instances manager
func NewInstancesManager(api instanceAPI, metricsAPI metricsAPI) *InstancesManager {
	return &InstancesManager{
		instances:  InstanceMap{},
		api:        api,
		metricsAPI: metricsAPI,
	}
}

// GetSubnet returns the subnet by subnet ID
//
// The returned subnet is immutable so it can be safely accessed
func (m *InstancesManager) GetSubnet(subnetID string) *types.Subnet {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	return m.subnets[subnetID]
}

// FindSubnetByTags returns the subnet with the most addresses matching VPC ID,
// availability zone and all required tags
//
// The returned subnet is immutable so it can be safely accessed
func (m *InstancesManager) FindSubnetByTags(vpcID, availabilityZone string, required types.Tags) (bestSubnet *types.Subnet) {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	for _, s := range m.subnets {
		if s.VpcID == vpcID && s.AvailabilityZone == availabilityZone && s.Tags.Match(required) {
			if bestSubnet == nil || bestSubnet.AvailableAddresses < s.AvailableAddresses {
				bestSubnet = s
			}
		}
	}

	return
}

// Resync fetches the list of EC2 instances and subnets and updates the local
// cache in the instanceManager
func (m *InstancesManager) Resync() {
	m.metricsAPI.IncResyncCount()

	vpcs, err := m.api.GetVpcs()
	if err != nil {
		log.WithError(err).Warning("Unable to synchronize EC2 VPC list")
		return
	}

	subnets, err := m.api.GetSubnets()
	if err != nil {
		log.WithError(err).Warning("Unable to retrieve EC2 subnets list")
		return
	}

	instances, err := m.api.GetInstances(vpcs, subnets)
	if err != nil {
		log.WithError(err).Warning("Unable to synchronize EC2 interface list")
		return
	}

	log.WithFields(logrus.Fields{
		"numENIs":    len(instances),
		"numVPCs":    len(vpcs),
		"numSubnets": len(subnets),
	}).Info("Synchronized ENI information")

	m.mutex.Lock()
	m.instances = instances
	m.subnets = subnets
	m.vpcs = vpcs
	m.mutex.Unlock()
}

// GetENI returns the ENI of an instance at a particular interface index
func (m *InstancesManager) GetENI(instanceID string, index int) *v2.ENI {
	for _, eni := range m.getENIs(instanceID) {
		if eni.Number == index {
			return eni
		}
	}

	return nil
}

// GetENIs returns the list of ENIs associated with a particular instance
func (m *InstancesManager) GetENIs(instanceID string) []*v2.ENI {
	return m.getENIs(instanceID)
}

// getENIs returns the list of ENIs associated with a particular instance
func (m *InstancesManager) getENIs(instanceID string) []*v2.ENI {
	enis := []*v2.ENI{}

	m.mutex.RLock()
	defer m.mutex.RUnlock()

	if i, ok := m.instances[instanceID]; ok {
		for _, e := range i.enis {
			enis = append(enis, e.DeepCopy())
		}
	}

	return enis
}
