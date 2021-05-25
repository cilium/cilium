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

	eniTypes "github.com/cilium/cilium/pkg/aws/eni/types"
	"github.com/cilium/cilium/pkg/aws/types"
	"github.com/cilium/cilium/pkg/ipam"
	ipamTypes "github.com/cilium/cilium/pkg/ipam/types"
	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/lock"

	"github.com/sirupsen/logrus"
)

// EC2API is the API surface used of the EC2 API
type EC2API interface {
	GetInstances(ctx context.Context, vpcs ipamTypes.VirtualNetworkMap, subnets ipamTypes.SubnetMap) (*ipamTypes.InstanceMap, error)
	GetSubnets(ctx context.Context) (ipamTypes.SubnetMap, error)
	GetVpcs(ctx context.Context) (ipamTypes.VirtualNetworkMap, error)
	GetSecurityGroups(ctx context.Context) (types.SecurityGroupMap, error)
	CreateNetworkInterface(ctx context.Context, toAllocate int32, subnetID, desc string, groups []string) (string, *eniTypes.ENI, error)
	AttachNetworkInterface(ctx context.Context, index int32, instanceID, eniID string) (string, error)
	DeleteNetworkInterface(ctx context.Context, eniID string) error
	ModifyNetworkInterface(ctx context.Context, eniID, attachmentID string, deleteOnTermination bool) error
	AssignPrivateIpAddresses(ctx context.Context, eniID string, addresses int32) error
	UnassignPrivateIpAddresses(ctx context.Context, eniID string, addresses []string) error
}

// InstancesManager maintains the list of instances. It must be kept up to date
// by calling resync() regularly.
type InstancesManager struct {
	mutex          lock.RWMutex
	instances      *ipamTypes.InstanceMap
	subnets        ipamTypes.SubnetMap
	vpcs           ipamTypes.VirtualNetworkMap
	securityGroups types.SecurityGroupMap
	api            EC2API
}

// NewInstancesManager returns a new instances manager
func NewInstancesManager(api EC2API) *InstancesManager {
	return &InstancesManager{
		instances: ipamTypes.NewInstanceMap(),
		api:       api,
	}
}

// CreateNode is called on discovery of a new node and returns the ENI node
// allocation implementation for the new node
func (m *InstancesManager) CreateNode(obj *v2.CiliumNode, n *ipam.Node) ipam.NodeOperations {
	return NewNode(n, obj, m)
}

// GetPoolQuota returns the number of available IPs in all IP pools
func (m *InstancesManager) GetPoolQuota() ipamTypes.PoolQuotaMap {
	pool := ipamTypes.PoolQuotaMap{}
	for subnetID, subnet := range m.GetSubnets(context.TODO()) {
		pool[ipamTypes.PoolID(subnetID)] = ipamTypes.PoolQuota{
			AvailabilityZone: subnet.AvailabilityZone,
			AvailableIPs:     subnet.AvailableAddresses,
		}
	}
	return pool
}

// GetSubnet returns the subnet by subnet ID
//
// The returned subnet is immutable so it can be safely accessed
func (m *InstancesManager) GetSubnet(subnetID string) *ipamTypes.Subnet {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	return m.subnets[subnetID]
}

// GetSubnets returns all the tracked subnets
//
// The returned subnetMap is immutable so it can be safely accessed
func (m *InstancesManager) GetSubnets(ctx context.Context) ipamTypes.SubnetMap {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	subnetsCopy := make(ipamTypes.SubnetMap)
	for k, v := range m.subnets {
		subnetsCopy[k] = v
	}

	return subnetsCopy
}

// FindSubnetByTags returns the subnet with the most addresses matching VPC ID,
// availability zone and all required tags
//
// The returned subnet is immutable so it can be safely accessed
func (m *InstancesManager) FindSubnetByTags(vpcID, availabilityZone string, required ipamTypes.Tags) (bestSubnet *ipamTypes.Subnet) {
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
func (m *InstancesManager) FindSecurityGroupByTags(vpcID string, required ipamTypes.Tags) []*types.SecurityGroup {
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
		"numInstances":      instances.NumInstances(),
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

// UpdateENI updates the ENI definition of an ENI for a particular instance. If
// the ENI is already known, the definition is updated, otherwise the ENI is
// added to the instance.
func (m *InstancesManager) UpdateENI(instanceID string, eni *eniTypes.ENI) {
	m.mutex.Lock()
	eniRevision := ipamTypes.InterfaceRevision{Resource: eni}
	m.instances.Update(instanceID, eniRevision)
	m.mutex.Unlock()
}

// ForeachInstance will iterate over each instance inside `instances`, and call
// `fn`. This function is read-locked for the entire execution.
func (m *InstancesManager) ForeachInstance(instanceID string, fn ipamTypes.InterfaceIterator) {
	// This is a safety net in case the InstanceID is not known for some
	// reason. If we don't know the instanceID, we also can't derive the
	// list of ENIs attached to this instance. Without this,
	// ForeachInstance() would return the ENIs of all instances.
	if instanceID == "" {
		log.Error("BUG: Inconsistent CiliumNode state. The InstanceID is not known")
		return
	}

	m.mutex.RLock()
	defer m.mutex.RUnlock()
	m.instances.ForeachInterface(instanceID, fn)
}
