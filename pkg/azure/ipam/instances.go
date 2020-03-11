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
	"fmt"
	"net"
	"time"

	"github.com/cilium/cilium/pkg/azure/types"
	"github.com/cilium/cilium/pkg/ipam"
	ipamTypes "github.com/cilium/cilium/pkg/ipam/types"
	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/lock"

	"github.com/cilium/ipam/service/ipallocator"
	"github.com/sirupsen/logrus"
)

type subnetAllocator struct {
	subnet    *ipamTypes.Subnet
	allocator *ipallocator.Range
}

// AzureAPI is the API surface used of the Azure API
type AzureAPI interface {
	GetInstances(ctx context.Context) (types.InstanceMap, error)
	GetVpcsAndSubnets(ctx context.Context) (ipamTypes.VirtualNetworkMap, ipamTypes.SubnetMap, error)
	AssignPrivateIpAddresses(ctx context.Context, subnetID, interfaceID string, ips []net.IP) error
}

// InstancesManager maintains the list of instances. It must be kept up to date
// by calling resync() regularly.
type InstancesManager struct {
	mutex      lock.RWMutex
	instances  types.InstanceMap
	vnets      ipamTypes.VirtualNetworkMap
	api        AzureAPI
	allocators map[string]*subnetAllocator
}

// NewInstancesManager returns a new instances manager
func NewInstancesManager(api AzureAPI) *InstancesManager {
	return &InstancesManager{
		instances: types.InstanceMap{},
		api:       api,
	}
}

// CreateNode is called on discovery of a new node and returns the ENI node
// allocation implementation for the new node
func (m *InstancesManager) CreateNode(obj *v2.CiliumNode, n *ipam.Node) ipam.NodeOperations {
	return &Node{k8sObj: obj, manager: m, node: n}
}

// GetPoolQuota returns the number of available IPs in all IP pools
func (m *InstancesManager) GetPoolQuota() ipamTypes.PoolQuotaMap {
	pool := ipamTypes.PoolQuotaMap{}

	m.mutex.RLock()
	for subnetID, subnet := range m.allocators {
		pool[ipamTypes.PoolID(subnetID)] = ipamTypes.PoolQuota{
			AvailableIPs: subnet.allocator.Free(),
		}
	}
	m.mutex.RUnlock()

	return pool
}

// getSubnet returns the subnet by subnet ID
//
// The returned subnet is immutable so it can be safely accessed
func (m *InstancesManager) getSubnet(subnetID string) *subnetAllocator {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	return m.allocators[subnetID]
}

// getSubnets returns all available subnets
func (m *InstancesManager) getSubnets() (subnets []*subnetAllocator) {
	m.mutex.RLock()
	for _, subnet := range m.allocators {
		subnets = append(subnets, subnet)
	}
	defer m.mutex.RUnlock()
	return
}

func newSubnetAllocator(subnet *ipamTypes.Subnet) (*subnetAllocator, error) {
	allocator, err := ipallocator.NewCIDRRange(subnet.CIDR.IPNet)
	if err != nil {
		return nil, fmt.Errorf("unable to create IP allocator: %s", err)
	}

	return &subnetAllocator{
		allocator: allocator,
		subnet:    subnet,
	}, nil
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

	instances, err := m.api.GetInstances(ctx)
	if err != nil {
		log.WithError(err).Warning("Unable to synchronize Azure instances list")
		return time.Time{}
	}

	log.WithFields(logrus.Fields{
		"numInstances":       len(instances),
		"numVirtualNetworks": len(vnets),
		"numSubnets":         len(subnets),
	}).Info("Synchronized Azure IPAM information")

	// Create subnet allocators for all identified subnets
	allocators := map[string]*subnetAllocator{}
	for id, subnet := range subnets {
		if subnet.CIDR == nil {
			continue
		}

		a, err := newSubnetAllocator(subnet)
		if err != nil {
			log.WithError(err).WithField("subnet", id).Warning("Unable to create allocator for subnet")
			continue
		}
		allocators[id] = a
	}

	// Reserve all known IP addresses in all known subnet allocators
	for _, instance := range instances {
		for _, iface := range instance.Interfaces {
			for _, address := range iface.Addresses {
				ip := net.ParseIP(address.IP)
				if ip != nil {
					if a, ok := allocators[address.Subnet]; ok {
						if err := a.allocator.Allocate(ip); err != nil {
							log.WithFields(logrus.Fields{
								"instance":  instance,
								"interface": iface.ID,
								"address":   address,
							}).WithError(err).Warning("Unable to allocate IP in internal allocator")
						}
					}
				} else {
					log.WithFields(logrus.Fields{
						"instance":  instance,
						"interface": iface.ID,
						"address":   address,
					}).Warning("Unable to parse IP of AzureAddress")
				}
			}
		}
	}

	m.mutex.Lock()
	m.instances = instances
	m.vnets = vnets
	m.allocators = allocators
	m.mutex.Unlock()

	return resyncStart
}

// GetInterfaces returns the list of interfaces associated with a particular instance
func (m *InstancesManager) GetInterfaces(instanceID string) []*types.AzureInterface {
	m.mutex.RLock()
	defer m.mutex.RUnlock()
	return m.instances.Get(instanceID)
}
