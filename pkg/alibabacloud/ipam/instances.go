// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ipam

import (
	"context"
	"fmt"
	"log/slog"
	"maps"

	"github.com/cilium/cilium/operator/pkg/ipam/nodemanager"
	"github.com/cilium/cilium/pkg/alibabacloud/types"
	"github.com/cilium/cilium/pkg/ipam/instances"
	ipamTypes "github.com/cilium/cilium/pkg/ipam/types"
	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/time"
)

// AlibabaCloudAPI is the API surface used of the ECS API
type AlibabaCloudAPI interface {
	GetInstance(ctx context.Context, vpcs ipamTypes.VirtualNetworkMap, subnets ipamTypes.SubnetMap, instanceID string) (*ipamTypes.Instance, error)
	GetInstances(ctx context.Context, vpcs ipamTypes.VirtualNetworkMap, subnets ipamTypes.SubnetMap) (*ipamTypes.InstanceMap, error)
	GetVSwitches(ctx context.Context) (ipamTypes.SubnetMap, error)
	GetVPC(ctx context.Context, vpcID string) (*ipamTypes.VirtualNetwork, error)
	GetVPCs(ctx context.Context) (ipamTypes.VirtualNetworkMap, error)
	GetSecurityGroups(ctx context.Context) (types.SecurityGroupMap, error)
	CreateNetworkInterface(ctx context.Context, secondaryPrivateIPCount int, vSwitchID string, groups []string, tags map[string]string) (string, *types.ENI, error)
	AttachNetworkInterface(ctx context.Context, instanceID, eniID string) error
	WaitENIAttached(ctx context.Context, eniID string) (string, error)
	DeleteNetworkInterface(ctx context.Context, eniID string) error
	AssignPrivateIPAddresses(ctx context.Context, eniID string, toAllocate int) ([]string, error)
	UnassignPrivateIPAddresses(ctx context.Context, eniID string, addresses []string) error
}

// InstancesManager maintains the list of instances. It must be kept up to date
// by calling resync() regularly.
type InstancesManager struct {
	// InstanceCache caches the instances and owns the locks; the fields
	// below marked as protected by the cache lock are read and written
	// through its Read and resync publish functions.
	*instances.InstanceCache

	logger *slog.Logger

	// The fields below are protected by the cache lock.
	vSwitches      ipamTypes.SubnetMap
	vpcs           ipamTypes.VirtualNetworkMap
	securityGroups types.SecurityGroupMap
	api            AlibabaCloudAPI
}

// NewInstancesManager returns a new instances manager
func NewInstancesManager(logger *slog.Logger, api AlibabaCloudAPI) *InstancesManager {
	return &InstancesManager{
		InstanceCache: instances.NewInstanceCache(),
		logger:        logger.With(subsysLogAttr...),
		api:           api,
	}
}

// CreateNode
func (m *InstancesManager) CreateNode(obj *v2.CiliumNode, node *nodemanager.Node) nodemanager.NodeOperations {
	return &Node{logger: m.logger, k8sObj: obj, manager: m, node: node, instanceID: node.InstanceID()}
}

// HasInstance, DeleteInstance and ForeachInstance are provided by the
// embedded InstanceCache.

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
// started or an error if it did not complete.
func (m *InstancesManager) Resync(ctx context.Context) (time.Time, error) {
	// ENIs from all instances will be refetched from the ECS API and updated
	// to the local cache.
	return m.FullResync(ctx, func(ctx context.Context) (*ipamTypes.InstanceMap, instances.PublishFunc, error) {
		vpcs, vSwitches, securityGroups, err := m.fetchNetworkState(ctx)
		if err != nil {
			return nil, nil, err
		}

		instanceMap, err := m.api.GetInstances(ctx, vpcs, vSwitches)
		if err != nil {
			return nil, nil, fmt.Errorf("synchronize ECS interface list: %w", err)
		}

		m.logger.Info(
			"Synchronized ENI information",
			logfields.NumInstances, instanceMap.NumInstances(),
			logfields.NumVPCs, len(vpcs),
			logfields.NumVSwitches, len(vSwitches),
			logfields.NumSecurityGroups, len(securityGroups),
		)

		return instanceMap, func() {
			m.vSwitches = vSwitches
			m.vpcs = vpcs
			m.securityGroups = securityGroups
		}, nil
	})
}

// InstanceSync fetches the ECS instance by the given ID and vSwitches and updates the local
// cache in the instanceManager. It returns the time when the resync has
// started or an error if it did not complete.
func (m *InstancesManager) InstanceSync(ctx context.Context, instanceID string) (time.Time, error) {
	return m.InstanceCache.InstanceSync(ctx, instanceID, func(ctx context.Context) (*ipamTypes.Instance, instances.PublishFunc, error) {
		vpcs, vSwitches, securityGroups, err := m.fetchNetworkState(ctx)
		if err != nil {
			return nil, nil, err
		}

		instance, err := m.api.GetInstance(ctx, vpcs, vSwitches, instanceID)
		if err != nil {
			return nil, nil, fmt.Errorf("synchronize ECS interface list for instance %s: %w", instanceID, err)
		}

		m.logger.Info(
			"Synchronized ENI information for the corresponding instance",
			logfields.InstanceID, instanceID,
			logfields.NumVPCs, len(vpcs),
			logfields.NumVSwitches, len(vSwitches),
			logfields.NumSecurityGroups, len(securityGroups),
		)

		return instance, func() {
			m.vSwitches = vSwitches
			m.vpcs = vpcs
			m.securityGroups = securityGroups
		}, nil
	})
}

// fetchNetworkState fetches the VPCs, vSwitches and security groups from the
// ECS API.
func (m *InstancesManager) fetchNetworkState(ctx context.Context) (ipamTypes.VirtualNetworkMap, ipamTypes.SubnetMap, types.SecurityGroupMap, error) {
	vpcs, err := m.api.GetVPCs(ctx)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("synchronize VPC list: %w", err)
	}

	vSwitches, err := m.api.GetVSwitches(ctx)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("retrieve VPC vSwitches list: %w", err)
	}

	securityGroups, err := m.api.GetSecurityGroups(ctx)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("retrieve ECS security group list: %w", err)
	}

	return vpcs, vSwitches, securityGroups, nil
}

// GetVSwitches returns all the tracked vSwitches
// The returned subnetMap is immutable so it can be safely accessed
func (m *InstancesManager) GetVSwitches() ipamTypes.SubnetMap {
	subnetsCopy := make(ipamTypes.SubnetMap)
	m.Read(func(_ *ipamTypes.InstanceMap) {
		maps.Copy(subnetsCopy, m.vSwitches)
	})
	return subnetsCopy
}

// GetVSwitch return vSwitch by id
func (m *InstancesManager) GetVSwitch(id string) (vSwitch *ipamTypes.Subnet) {
	m.Read(func(_ *ipamTypes.InstanceMap) {
		vSwitch = m.vSwitches[id]
	})
	return vSwitch
}

// ForeachInstance, HasInstance and DeleteInstance are provided by the
// embedded InstanceCache.

// UpdateENI updates the ENI definition of an ENI for a particular instance. If
// the ENI is already known, the definition is updated, otherwise the ENI is
// added to the instance.
func (m *InstancesManager) UpdateENI(instanceID string, eni *types.ENI) {
	m.UpdateInterface(instanceID, eni)
}

// FindOneVSwitch returns the vSwitch with the most available addresses, matching vpc and az.
// If we have explicit ID or tag constraints, chose a matching vSwitch. ID constraints take
// precedence.
func (m *InstancesManager) FindOneVSwitch(spec types.Spec, toAllocate int) *ipamTypes.Subnet {
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
		if bestSubnet == nil || bestSubnet.AvailableAddresses < vSwitch.AvailableAddresses {
			bestSubnet = vSwitch
		}
	}
	return bestSubnet
}

// FindVSwitchByIDs returns the vSwitch within a provided list of vSwitch IDs with the most available addresses,
// matching vpc and az.
func (m *InstancesManager) FindVSwitchByIDs(spec types.Spec, toAllocate int) (bestSubnet *ipamTypes.Subnet) {
	m.Read(func(_ *ipamTypes.InstanceMap) {
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
				if bestSubnet == nil || bestSubnet.AvailableAddresses < vSwitch.AvailableAddresses {
					bestSubnet = vSwitch
				}
			}
		}
	})
	return bestSubnet
}

// FindSecurityGroupByTags returns the security groups matching VPC ID and all required tags
// The returned security groups slice is immutable so it can be safely accessed
func (m *InstancesManager) FindSecurityGroupByTags(vpcID string, required ipamTypes.Tags) []*types.SecurityGroup {
	securityGroups := []*types.SecurityGroup{}
	m.Read(func(_ *ipamTypes.InstanceMap) {
		for _, securityGroup := range m.securityGroups {
			if securityGroup.VPCID == vpcID && securityGroup.Tags.Match(required) {
				securityGroups = append(securityGroups, securityGroup)
			}
		}
	})
	return securityGroups
}
