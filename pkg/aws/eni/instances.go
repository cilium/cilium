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
	"context"
	"time"

	"github.com/cilium/cilium/pkg/aws/types"
	"github.com/cilium/cilium/pkg/ipam"
	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/lock"

	"github.com/sirupsen/logrus"
)

// EC2API is the API surface used of the EC2 API
type EC2API interface {
	GetInstances(ctx context.Context, vpcs ipam.VirtualNetworkMap, subnets ipam.SubnetMap) (types.InstanceMap, error)
	GetSubnets(ctx context.Context) (ipam.SubnetMap, error)
	GetVpcs(ctx context.Context) (ipam.VirtualNetworkMap, error)
	GetSecurityGroups(ctx context.Context) (types.SecurityGroupMap, error)

	CreateNetworkInterface(ctx context.Context, toAllocate int64, subnetID, desc string, groups []string) (string, *v2.ENI, error)
	AttachNetworkInterface(ctx context.Context, index int64, instanceID, eniID string) (string, error)
	DeleteNetworkInterface(ctx context.Context, eniID string) error
	ModifyNetworkInterface(ctx context.Context, eniID, attachmentID string, deleteOnTermination bool) error

	AssignPrivateIpAddresses(ctx context.Context, eniID string, addresses int64) error
	UnassignPrivateIpAddresses(ctx context.Context, eniID string, addresses []string) error
	TagENI(ctx context.Context, eniID string, eniTags map[string]string) error
}

// InstancesManager maintains the list of instances. It must be kept up to date
// by calling resync() regularly.
type InstancesManager struct {
	mutex          lock.RWMutex
	instances      types.InstanceMap
	subnets        ipam.SubnetMap
	vpcs           ipam.VirtualNetworkMap
	securityGroups types.SecurityGroupMap
	api            EC2API
	eniTags        map[string]string
}

// NewInstancesManager returns a new instances manager
func NewInstancesManager(api EC2API, eniTags map[string]string) *InstancesManager {
	return &InstancesManager{
		instances: types.InstanceMap{},
		api:       api,
		eniTags:   eniTags,
	}
}

// CreateNode is called on discovery of a new node and returns the ENI node
// allocation implementation for the new node
func (m *InstancesManager) CreateNode(obj *v2.CiliumNode, n *ipam.Node) ipam.NodeOperations {
	return &Node{k8sObj: obj, manager: m, node: n}
}

// GetPoolQuota returns the number of available IPs in all IP pools
func (n *InstancesManager) GetPoolQuota() ipam.PoolQuotaMap {
	pool := ipam.PoolQuotaMap{}
	for subnetID, subnet := range n.GetSubnets(context.TODO()) {
		pool[ipam.PoolID(subnetID)] = ipam.PoolQuota{
			AvailabilityZone: subnet.AvailabilityZone,
			AvailableIPs:     subnet.AvailableAddresses,
		}
	}
	return pool
}

// GetSubnet returns the subnet by subnet ID
//
// The returned subnet is immutable so it can be safely accessed
func (m *InstancesManager) GetSubnet(subnetID string) *ipam.Subnet {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	return m.subnets[subnetID]
}

// GetSubnets returns all the tracked subnets
//
// The returned subnetMap is immutable so it can be safely accessed
func (m *InstancesManager) GetSubnets(ctx context.Context) ipam.SubnetMap {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	subnetsCopy := make(ipam.SubnetMap)
	for k, v := range m.subnets {
		subnetsCopy[k] = v
	}

	return subnetsCopy
}

// FindSubnetByTags returns the subnet with the most addresses matching VPC ID,
// availability zone and all required tags
//
// The returned subnet is immutable so it can be safely accessed
func (m *InstancesManager) FindSubnetByTags(vpcID, availabilityZone string, required ipam.Tags) (bestSubnet *ipam.Subnet) {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	for _, s := range m.subnets {
		if s.VirtualNetworkID == vpcID && s.AvailabilityZone == availabilityZone && s.Tags.Match(required) {
			if bestSubnet == nil || bestSubnet.AvailableAddresses < s.AvailableAddresses {
				bestSubnet = s
			}
		}
	}

	return
}

// FindSecurityGroupByTags returns the security groups matching VPC ID and all required tags
//
// The returned security groups slice is immutable so it can be safely accessed
func (m *InstancesManager) FindSecurityGroupByTags(vpcID string, required ipam.Tags) []*types.SecurityGroup {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	securityGroups := []*types.SecurityGroup{}
	for _, securityGroup := range m.securityGroups {
		if securityGroup.VpcID == vpcID && securityGroup.Tags.Match(required) {
			securityGroups = append(securityGroups, securityGroup)
		}
	}

	return securityGroups
}

// Resync fetches the list of EC2 instances and subnets and updates the local
// cache in the instanceManager. It returns the time when the resync has
// started or time.Time{} if it did not complete.
func (m *InstancesManager) Resync(ctx context.Context) time.Time {
	resyncStart := time.Now()

	vpcs, err := m.api.GetVpcs(ctx)
	if err != nil {
		log.WithError(err).Warning("Unable to synchronize EC2 VPC list")
		return time.Time{}
	}

	subnets, err := m.api.GetSubnets(ctx)
	if err != nil {
		log.WithError(err).Warning("Unable to retrieve EC2 subnets list")
		return time.Time{}
	}

	securityGroups, err := m.api.GetSecurityGroups(ctx)
	if err != nil {
		log.WithError(err).Warning("Unable to retrieve EC2 security group list")
		return time.Time{}
	}

	instances, err := m.api.GetInstances(ctx, vpcs, subnets)
	if err != nil {
		log.WithError(err).Warning("Unable to synchronize EC2 interface list")
		return time.Time{}
	}

	log.WithFields(logrus.Fields{
		"numENIs":           len(instances),
		"numVPCs":           len(vpcs),
		"numSubnets":        len(subnets),
		"numSecurityGroups": len(securityGroups),
	}).Info("Synchronized ENI information")

	m.mutex.Lock()
	m.instances = instances
	m.subnets = subnets
	m.vpcs = vpcs
	m.securityGroups = securityGroups
	m.mutex.Unlock()

	return resyncStart
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
	m.mutex.RLock()
	defer m.mutex.RUnlock()
	return m.instances.Get(instanceID)
}

// UpdateENI updates the ENI definition of an ENI for a particular instance. If
// the ENI is already known, the definition is updated, otherwise the ENI is
// added to the instance.
func (m *InstancesManager) UpdateENI(instanceID string, eni *v2.ENI) {
	m.mutex.Lock()
	m.instances.Update(instanceID, eni)
	m.mutex.Unlock()
}
