// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package eni

import (
	"context"
	"time"

	"github.com/sirupsen/logrus"

	eniTypes "github.com/cilium/cilium/pkg/alibabacloud/eni/types"
	"github.com/cilium/cilium/pkg/alibabacloud/types"
	"github.com/cilium/cilium/pkg/ipam"
	ipamTypes "github.com/cilium/cilium/pkg/ipam/types"
	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/lock"
)

// AlibabaCloudAPI is the API surface used of the ECS API
type AlibabaCloudAPI interface {
	GetInstances(ctx context.Context, vpcs ipamTypes.VirtualNetworkMap, subnets ipamTypes.SubnetMap) (*ipamTypes.InstanceMap, error)
	GetVSwitches(ctx context.Context) (ipamTypes.SubnetMap, error)
	GetVPC(ctx context.Context, vpcID string) (*ipamTypes.VirtualNetwork, error)
	GetVPCs(ctx context.Context) (ipamTypes.VirtualNetworkMap, error)
	GetSecurityGroups(ctx context.Context) (types.SecurityGroupMap, error)
	CreateNetworkInterface(ctx context.Context, secondaryPrivateIPCount int, vSwitchID string, groups []string, tags map[string]string) (string, *eniTypes.ENI, error)
	AttachNetworkInterface(ctx context.Context, instanceID, eniID string) error
	WaitENIAttached(ctx context.Context, eniID string) (string, error)
	DeleteNetworkInterface(ctx context.Context, eniID string) error
	AssignPrivateIPAddresses(ctx context.Context, eniID string, toAllocate int) ([]string, error)
	UnassignPrivateIPAddresses(ctx context.Context, eniID string, addresses []string) error
}

// InstancesManager maintains the list of instances. It must be kept up to date
// by calling resync() regularly.
type InstancesManager struct {
	mutex          lock.RWMutex
	instances      *ipamTypes.InstanceMap
	vSwitches      ipamTypes.SubnetMap
	vpcs           ipamTypes.VirtualNetworkMap
	securityGroups types.SecurityGroupMap
	api            AlibabaCloudAPI
}

// NewInstancesManager returns a new instances manager
func NewInstancesManager(api AlibabaCloudAPI) *InstancesManager {
	return &InstancesManager{
		instances: ipamTypes.NewInstanceMap(),
		api:       api,
	}
}

// CreateNode
func (m *InstancesManager) CreateNode(obj *v2.CiliumNode, node *ipam.Node) ipam.NodeOperations {
	return &Node{k8sObj: obj, manager: m, node: node, instanceID: node.InstanceID()}
}

// HasInstance returns whether the instance is in instances
func (m *InstancesManager) HasInstance(instanceID string) bool {
	m.mutex.RLock()
	defer m.mutex.RUnlock()
	return m.instances.Exists(instanceID)
}

// GetPoolQuota returns the number of available IPs in all IP pools
func (m *InstancesManager) GetPoolQuota() ipamTypes.PoolQuotaMap {
	pool := ipamTypes.PoolQuotaMap{}
	for subnetID, subnet := range m.GetVSwitches() {
		pool[ipamTypes.PoolID(subnetID)] = ipamTypes.PoolQuota{
			AvailabilityZone: subnet.AvailabilityZone,
			AvailableIPs:     subnet.AvailableAddresses,
		}
	}
	return pool
}

// Resync fetches the list of ECS instances and vSwitches and updates the local
// cache in the instanceManager. It returns the time when the resync has
// started or time.Time{} if it did not complete.
func (m *InstancesManager) Resync(ctx context.Context) time.Time {
	resyncStart := time.Now()

	vpcs, err := m.api.GetVPCs(ctx)
	if err != nil {
		log.WithError(err).Warning("Unable to synchronize VPC list")
		return time.Time{}
	}

	vSwitches, err := m.api.GetVSwitches(ctx)
	if err != nil {
		log.WithError(err).Warning("Unable to retrieve VPC vSwitches list")
		return time.Time{}
	}

	securityGroups, err := m.api.GetSecurityGroups(ctx)
	if err != nil {
		log.WithError(err).Warning("Unable to retrieve ECS security group list")
		return time.Time{}
	}

	instances, err := m.api.GetInstances(ctx, vpcs, vSwitches)
	if err != nil {
		log.WithError(err).Warning("Unable to synchronize ECS interface list")
		return time.Time{}
	}

	log.WithFields(logrus.Fields{
		"numInstances":      instances.NumInstances(),
		"numVPCs":           len(vpcs),
		"numVSwitches":      len(vSwitches),
		"numSecurityGroups": len(securityGroups),
	}).Info("Synchronized ENI information")

	m.mutex.Lock()
	m.instances = instances
	m.vSwitches = vSwitches
	m.vpcs = vpcs
	m.securityGroups = securityGroups
	m.mutex.Unlock()

	return resyncStart
}

// GetVSwitches returns all the tracked vSwitches
// The returned subnetMap is immutable so it can be safely accessed
func (m *InstancesManager) GetVSwitches() ipamTypes.SubnetMap {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	subnetsCopy := make(ipamTypes.SubnetMap)
	for k, v := range m.vSwitches {
		subnetsCopy[k] = v
	}

	return subnetsCopy
}

// GetVSwitch return vSwitch by id
func (m *InstancesManager) GetVSwitch(id string) *ipamTypes.Subnet {
	m.mutex.RLock()
	defer m.mutex.RUnlock()
	return m.vSwitches[id]
}

// ForeachInstance will iterate over each instance inside `instances`, and call
// `fn`. This function is read-locked for the entire execution.
func (m *InstancesManager) ForeachInstance(instanceID string, fn ipamTypes.InterfaceIterator) {
	m.mutex.RLock()
	defer m.mutex.RUnlock()
	m.instances.ForeachInterface(instanceID, fn)
}

// UpdateENI updates the ENI definition of an ENI for a particular instance. If
// the ENI is already known, the definition is updated, otherwise the ENI is
// added to the instance.
func (m *InstancesManager) UpdateENI(instanceID string, eni *eniTypes.ENI) {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	eniRevision := ipamTypes.InterfaceRevision{Resource: eni}
	m.instances.Update(instanceID, eniRevision)
}

// FindOneVSwitch returns the vSwitch with the fewest available addresses, matching vpc and az.
// If we have explicit ID or tag constraints, chose a matching vSwitch. ID constraints take
// precedence.
func (m *InstancesManager) FindOneVSwitch(spec eniTypes.Spec, toAllocate int) *ipamTypes.Subnet {
	if len(spec.VSwitches) > 0 {
		return m.FindVSwitchByIDs(spec, toAllocate)
	}
	var bestSubnet *ipamTypes.Subnet
	for _, vSwitch := range m.GetVSwitches() {
		if vSwitch.VirtualNetworkID != spec.VPCID {
			continue
		}
		if vSwitch.AvailabilityZone != spec.AvailabilityZone {
			continue
		}
		if vSwitch.AvailableAddresses < toAllocate {
			continue
		}
		if !vSwitch.Tags.Match(spec.VSwitchTags) {
			continue
		}
		if bestSubnet == nil || bestSubnet.AvailableAddresses > vSwitch.AvailableAddresses {
			bestSubnet = vSwitch
		}
	}
	return bestSubnet
}

// FindVSwitchByIDs returns the vSwitch within a provided list of vSwitch IDs with the fewest available addresses,
// matching vpc and az.
func (m *InstancesManager) FindVSwitchByIDs(spec eniTypes.Spec, toAllocate int) *ipamTypes.Subnet {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	var bestSubnet *ipamTypes.Subnet
	for _, vSwitch := range m.vSwitches {
		if vSwitch.VirtualNetworkID != spec.VPCID || vSwitch.AvailabilityZone != spec.AvailabilityZone {
			continue
		}
		if vSwitch.AvailableAddresses < toAllocate {
			continue
		}
		for _, vSwitchID := range spec.VSwitches {
			if vSwitch.ID != vSwitchID {
				continue
			}
			if bestSubnet == nil || bestSubnet.AvailableAddresses > vSwitch.AvailableAddresses {
				bestSubnet = vSwitch
			}
		}
	}
	return bestSubnet
}

// FindSecurityGroupByTags returns the security groups matching VPC ID and all required tags
// The returned security groups slice is immutable so it can be safely accessed
func (m *InstancesManager) FindSecurityGroupByTags(vpcID string, required ipamTypes.Tags) []*types.SecurityGroup {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	securityGroups := []*types.SecurityGroup{}
	for _, securityGroup := range m.securityGroups {
		if securityGroup.VPCID == vpcID && securityGroup.Tags.Match(required) {
			securityGroups = append(securityGroups, securityGroup)
		}
	}

	return securityGroups
}

// DeleteInstance delete instance from m.instances
func (m *InstancesManager) DeleteInstance(instanceID string) {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	m.instances.Delete(instanceID)
}
