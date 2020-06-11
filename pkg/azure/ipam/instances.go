// Copyright 2019-2020 Authors of Cilium
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

package ipam

import (
	"context"
	"time"

	"github.com/cilium/cilium/pkg/ipam"
	ipamTypes "github.com/cilium/cilium/pkg/ipam/types"
	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/lock"

	"github.com/sirupsen/logrus"
)

// AzureAPI is the API surface used of the Azure API
type AzureAPI interface {
	GetInstances(ctx context.Context, subnets ipamTypes.SubnetMap) (*ipamTypes.InstanceMap, error)
	GetVpcsAndSubnets(ctx context.Context) (ipamTypes.VirtualNetworkMap, ipamTypes.SubnetMap, error)
	AssignPrivateIpAddressesVM(ctx context.Context, subnetID, interfaceName string, addresses int) error
	AssignPrivateIpAddressesVMSS(ctx context.Context, instanceID, vmssName, subnetID, interfaceName string, addresses int) error
}

// InstancesManager maintains the list of instances. It must be kept up to date
// by calling resync() regularly.
type InstancesManager struct {
	mutex     lock.RWMutex
	instances *ipamTypes.InstanceMap
	vnets     ipamTypes.VirtualNetworkMap
	subnets   ipamTypes.SubnetMap
	api       AzureAPI
}

// NewInstancesManager returns a new instances manager
func NewInstancesManager(api AzureAPI) *InstancesManager {
	return &InstancesManager{
		instances: ipamTypes.NewInstanceMap(),
		api:       api,
	}
}

// CreateNode is called on discovery of a new node
func (m *InstancesManager) CreateNode(obj *v2.CiliumNode, n *ipam.Node) ipam.NodeOperations {
	return &Node{manager: m, node: n}
}

// GetPoolQuota returns the number of available IPs in all IP pools
func (m *InstancesManager) GetPoolQuota() (quota ipamTypes.PoolQuotaMap) {
	m.mutex.RLock()
	pool := ipamTypes.PoolQuotaMap{}
	for subnetID, subnet := range m.subnets {
		pool[ipamTypes.PoolID(subnetID)] = ipamTypes.PoolQuota{
			AvailableIPs: subnet.AvailableAddresses,
		}
	}
	m.mutex.RUnlock()
	return pool
}

// GetPoolQuota returns the number of available IPs in all IP pools
func (m *InstancesManager) FindSubnetForAllocation(preferredPoolIDs []ipamTypes.PoolID) (ipamTypes.PoolID, int) {
	m.mutex.RLock()
	defer m.mutex.RUnlock()
	return m.subnets.FirstSubnetWithAvailableAddresses(preferredPoolIDs)
}

// Resync fetches the list of EC2 instances and subnets and updates the local
// cache in the instanceManager. It returns the time when the resync has
// started or time.Time{} if it did not complete.
func (m *InstancesManager) Resync(ctx context.Context) time.Time {
	resyncStart := time.Now()

	vnets, subnets, err := m.api.GetVpcsAndSubnets(ctx)
	if err != nil {
		log.WithError(err).Warning("Unable to synchronize Azure virtualnetworks list")
		return time.Time{}
	}

	instances, err := m.api.GetInstances(ctx, subnets)
	if err != nil {
		log.WithError(err).Warning("Unable to synchronize Azure instances list")
		return time.Time{}
	}

	log.WithFields(logrus.Fields{
		"numInstances":       instances.NumInstances(),
		"numVirtualNetworks": len(vnets),
		"numSubnets":         len(subnets),
	}).Info("Synchronized Azure IPAM information")

	m.mutex.Lock()
	m.instances = instances
	m.vnets = vnets
	m.subnets = subnets
	m.mutex.Unlock()

	return resyncStart
}
