// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

// Copyright 2017 Lyft, Inc.

package eni

import (
	"context"
	"log/slog"
	"maps"
	"slices"

	ec2_types "github.com/aws/aws-sdk-go-v2/service/ec2/types"

	"github.com/cilium/cilium/pkg/aws/eni/limits"
	eniTypes "github.com/cilium/cilium/pkg/aws/eni/types"
	"github.com/cilium/cilium/pkg/aws/types"
	"github.com/cilium/cilium/pkg/ipam"
	ipamTypes "github.com/cilium/cilium/pkg/ipam/types"
	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/time"
)

// EC2API is the API surface used of the EC2 API
type EC2API interface {
	GetInstance(ctx context.Context, vpcs ipamTypes.VirtualNetworkMap, subnets ipamTypes.SubnetMap, instanceID string) (*ipamTypes.Instance, error)
	GetInstances(ctx context.Context, vpcs ipamTypes.VirtualNetworkMap, subnets ipamTypes.SubnetMap) (*ipamTypes.InstanceMap, error)
	GetSubnets(ctx context.Context) (ipamTypes.SubnetMap, error)
	GetVpcs(ctx context.Context) (ipamTypes.VirtualNetworkMap, error)
	GetRouteTables(ctx context.Context) (ipamTypes.RouteTableMap, error)
	GetSecurityGroups(ctx context.Context) (types.SecurityGroupMap, error)
	GetDetachedNetworkInterfaces(ctx context.Context, tags ipamTypes.Tags, maxResults int32) ([]string, error)
	CreateNetworkInterface(ctx context.Context, toAllocate int32, subnetID, desc string, groups []string, allocatePrefixes bool) (string, *eniTypes.ENI, error)
	AttachNetworkInterface(ctx context.Context, index int32, instanceID, eniID string) (string, error)
	DeleteNetworkInterface(ctx context.Context, eniID string) error
	ModifyNetworkInterface(ctx context.Context, eniID, attachmentID string, deleteOnTermination bool) error
	AssignPrivateIpAddresses(ctx context.Context, eniID string, addresses int32) ([]string, error)
	UnassignPrivateIpAddresses(ctx context.Context, eniID string, addresses []string) error
	AssignENIPrefixes(ctx context.Context, eniID string, prefixes int32) error
	UnassignENIPrefixes(ctx context.Context, eniID string, prefixes []string) error
	GetInstanceTypes(context.Context) ([]ec2_types.InstanceTypeInfo, error)
	AssociateEIP(ctx context.Context, instanceID string, eipTags ipamTypes.Tags) (string, error)
}

// InstancesManager maintains the list of instances. It must be kept up to date
// by calling resync() regularly.
type InstancesManager struct {
	logger *slog.Logger
	// resyncLock ensures instance incremental resync do not run at the same time as a full API resync
	resyncLock lock.RWMutex

	// mutex protects the fields below
	mutex          lock.RWMutex
	instances      *ipamTypes.InstanceMap
	subnets        ipamTypes.SubnetMap
	vpcs           ipamTypes.VirtualNetworkMap
	routeTables    ipamTypes.RouteTableMap
	securityGroups types.SecurityGroupMap
	api            EC2API
	limitsGetter   *limits.LimitsGetter
}

// NewInstancesManager returns a new instances manager
func NewInstancesManager(logger *slog.Logger, api EC2API) (*InstancesManager, error) {

	m := &InstancesManager{
		logger:    logger.With(subsysLogAttr...),
		instances: ipamTypes.NewInstanceMap(),
		api:       api,
	}

	limitsGetter, err := limits.NewLimitsGetter(logger, api, limits.TriggerMinInterval, limits.EC2apiTimeout, limits.EC2apiRetryCount)
	if err != nil {
		return nil, err
	}
	m.limitsGetter = limitsGetter
	return m, nil
}

// CreateNode is called on discovery of a new node and returns the ENI node
// allocation implementation for the new node
func (m *InstancesManager) CreateNode(obj *v2.CiliumNode, n *ipam.Node) ipam.NodeOperations {
	return NewNode(n, obj, m)
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
	maps.Copy(subnetsCopy, m.subnets)

	return subnetsCopy
}

// FindSubnetByIDs returns the subnet with the most addresses matching VPC ID,
// availability zone within a provided list of subnet ids
//
// The returned subnet is immutable so it can be safely accessed
func (m *InstancesManager) FindSubnetByIDs(vpcID, availabilityZone string, subnetIDs []string) (bestSubnet *ipamTypes.Subnet) {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	for _, s := range m.subnets {
		if s.VirtualNetworkID == vpcID && s.AvailabilityZone == availabilityZone {
			for _, subnetID := range subnetIDs {
				if s.ID == subnetID {
					if bestSubnet == nil || bestSubnet.AvailableAddresses < s.AvailableAddresses {
						bestSubnet = s
					}
					continue
				}
			}
		}
	}

	return
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
	// Full API resync should block the instance incremental resync from all nodes.
	m.resyncLock.Lock()
	defer m.resyncLock.Unlock()
	// An empty instanceID indicates the full resync.
	return m.resync(ctx, "")
}

func (m *InstancesManager) resync(ctx context.Context, instanceID string) time.Time {
	resyncStart := time.Now()

	vpcs, err := m.api.GetVpcs(ctx)
	if err != nil {
		m.logger.Warn("Unable to synchronize EC2 VPC list", logfields.Error, err)
		return time.Time{}
	}

	subnets, err := m.api.GetSubnets(ctx)
	if err != nil {
		m.logger.Warn("Unable to retrieve EC2 subnets list", logfields.Error, err)
		return time.Time{}
	}

	securityGroups, err := m.api.GetSecurityGroups(ctx)
	if err != nil {
		m.logger.Warn("Unable to retrieve EC2 security group list", logfields.Error, err)
		return time.Time{}
	}
	routeTables, err := m.api.GetRouteTables(ctx)
	if err != nil {
		m.logger.Warn("Unable to retrieve EC2 route table list", logfields.Error, err)
		return time.Time{}
	}

	// An empty instanceID indicates that this is full resync, ENIs from all instances
	// will be refetched from EC2 API and updated to the local cache. Otherwise only
	// the given instance will be updated.
	if instanceID == "" {
		instances, err := m.api.GetInstances(ctx, vpcs, subnets)
		if err != nil {
			m.logger.Warn("Unable to synchronize EC2 interface list", logfields.Error, err)
			return time.Time{}
		}

		m.logger.Info(
			"Synchronized ENI information",
			logfields.NumInstances, instances.NumInstances(),
			logfields.NumVPCs, len(vpcs),
			logfields.NumSubnets, len(subnets),
			logfields.NumRouteTables, len(routeTables),
			logfields.NumSecurityGroups, len(securityGroups),
		)

		m.mutex.Lock()
		defer m.mutex.Unlock()
		m.instances = instances
	} else {
		instance, err := m.api.GetInstance(ctx, vpcs, subnets, instanceID)
		if err != nil {
			m.logger.Warn("Unable to synchronize EC2 interface list", logfields.Error, err)
			return time.Time{}
		}

		m.logger.Info(
			"Synchronized ENI information for the corresponding instance",
			logfields.InstanceID, instanceID,
			logfields.NumVPCs, len(vpcs),
			logfields.NumSubnets, len(subnets),
			logfields.NumRouteTables, len(routeTables),
			logfields.NumSecurityGroups, len(securityGroups),
		)

		m.mutex.Lock()
		defer m.mutex.Unlock()
		m.instances.UpdateInstance(instanceID, instance)
	}

	m.subnets = subnets
	m.vpcs = vpcs
	m.securityGroups = securityGroups
	m.routeTables = routeTables

	return resyncStart
}

func (m *InstancesManager) InstanceSync(ctx context.Context, instanceID string) time.Time {
	// Instance incremental resync from different nodes should be executed in parallel,
	// but must block the full API resync.
	m.resyncLock.RLock()
	defer m.resyncLock.RUnlock()
	return m.resync(ctx, instanceID)
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

func (m *InstancesManager) AddIPsToENI(instanceID string, eniID string, ips []string) {
	m.modifyIPsToENI(instanceID, eniID, ips, true)
}

func (m *InstancesManager) RemoveIPsFromENI(instanceID string, eniID string, ips []string) {
	m.modifyIPsToENI(instanceID, eniID, ips, false)
}

func (m *InstancesManager) modifyIPsToENI(instanceID string, eniID string, ips []string, isAdd bool) {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	ifaces, ok := m.instances.GetInterface(instanceID, eniID)
	if !ok {
		m.logger.Warn(
			"ENI not found",
			logfields.InstanceID, instanceID,
			logfields.ENI, eniID,
		)
		return
	}

	eniIntf := ifaces.Resource.DeepCopyInterface()
	eni, ok := eniIntf.(*eniTypes.ENI)
	if !ok {
		m.logger.Warn(
			"Unexpected resource type, expected *eniTypes.ENI",
			logfields.InstanceID, instanceID,
			logfields.ENI, eniID,
		)
		return
	}
	if isAdd {
		for _, ip := range ips {
			if !slices.Contains(eni.Addresses, ip) {
				eni.Addresses = append(eni.Addresses, ip)
			}
		}
	} else {
		for _, ip := range ips {
			eni.Addresses = slices.DeleteFunc(eni.Addresses, func(addr string) bool {
				return addr == ip
			})
		}
	}
	m.instances.Update(instanceID, ipamTypes.InterfaceRevision{Resource: eni})
}

// ForeachInstance will iterate over each interface for a particular instance inside `instances`
// and call `fn`.
// This function is read-locked for the entire execution.
func (m *InstancesManager) ForeachInstance(instanceID string, fn ipamTypes.InterfaceIterator) {
	// This is a safety net in case the InstanceID is not known for some
	// reason. If we don't know the instanceID, we also can't derive the
	// list of ENIs attached to this instance. Without this,
	// ForeachInstance() would return the ENIs of all instances.
	if instanceID == "" {
		m.logger.Error("BUG: Inconsistent CiliumNode state. The InstanceID is not known")
		return
	}

	m.mutex.RLock()
	defer m.mutex.RUnlock()
	m.instances.ForeachInterface(instanceID, fn)
}

// DeleteInstance delete instance from m.instances
func (m *InstancesManager) DeleteInstance(instanceID string) {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	m.instances.Delete(instanceID)
}
