// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ipam

import (
	"context"
	"log/slog"

	"github.com/cilium/cilium/pkg/ipam"
	ipamTypes "github.com/cilium/cilium/pkg/ipam/types"
	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/time"
)

// AzureAPI is the API surface used of the Azure API
type AzureAPI interface {
	GetInstance(ctx context.Context, subnets ipamTypes.SubnetMap, instanceID string) (*ipamTypes.Instance, error)
	GetInstances(ctx context.Context, subnets ipamTypes.SubnetMap) (*ipamTypes.InstanceMap, error)
	GetVpcsAndSubnets(ctx context.Context) (ipamTypes.VirtualNetworkMap, ipamTypes.SubnetMap, error)
	GetNodesSubnets(ctx context.Context, nodeSubnetIDs []string) (ipamTypes.VirtualNetworkMap, ipamTypes.SubnetMap, error)
	AssignPrivateIpAddressesVM(ctx context.Context, subnetID, interfaceName string, addresses int) error
	AssignPrivateIpAddressesVMSS(ctx context.Context, instanceID, vmssName, subnetID, interfaceName string, addresses int) error
}

// InstancesManager maintains the list of instances. It must be kept up to date
// by calling Resync() regularly.
type InstancesManager struct {
	logger *slog.Logger
	// resyncLock ensures instance incremental resync do not run at the same time as a full API resync
	resyncLock lock.RWMutex

	// mutex protects the fields below
	mutex     lock.RWMutex
	instances *ipamTypes.InstanceMap
	vnets     ipamTypes.VirtualNetworkMap
	subnets   ipamTypes.SubnetMap
	api       AzureAPI
}

// NewInstancesManager returns a new instances manager
func NewInstancesManager(logger *slog.Logger, api AzureAPI) *InstancesManager {
	return &InstancesManager{
		logger:    logger.With(subsysLogAttr...),
		instances: ipamTypes.NewInstanceMap(),
		api:       api,
	}
}

// CreateNode is called on discovery of a new node
func (m *InstancesManager) CreateNode(obj *v2.CiliumNode, n *ipam.Node) ipam.NodeOperations {
	return &Node{manager: m, node: n}
}

// HasInstance returns whether the instance is in instances
func (m *InstancesManager) HasInstance(instanceID string) bool {
	m.mutex.RLock()
	defer m.mutex.RUnlock()
	return m.instances.Exists(instanceID)
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

// Resync fetches the list of instances and subnets and updates the local
// cache in the instanceManager. It returns the time when the resync has
// started or time.Time{} if it did not complete.
func (m *InstancesManager) Resync(ctx context.Context) time.Time {
	// Full API resync should block the instance incremental resync from all nodes.
	m.resyncLock.Lock()
	defer m.resyncLock.Unlock()
	return m.resyncInstances(ctx)
}

// resyncInstance only resyncs a given instance
func (m *InstancesManager) resyncInstance(ctx context.Context, instanceID string) time.Time {
	resyncStart := time.Now()

	// First get the instance with empty subnet map to extract subnet IDs
	instance, err := m.api.GetInstance(ctx, ipamTypes.SubnetMap{}, instanceID)
	if err != nil {
		m.logger.Warn("Unable to synchronize Azure instance interface list",
			logfields.Error, err,
			logfields.InstanceID, instanceID,
		)
		return time.Time{}
	}
	
	// Extract subnet IDs from this instance
	instanceMap := ipamTypes.NewInstanceMap()
	instanceMap.UpdateInstance(instanceID, instance)
	nodeSubnetIDs := m.extractSubnetIDs(instanceMap)
	
	// Query targeted subnets or fall back to full discovery
	var vnets ipamTypes.VirtualNetworkMap
	var subnets ipamTypes.SubnetMap
	
	if len(nodeSubnetIDs) > 0 {
		vnets, subnets, err = m.api.GetNodesSubnets(ctx, nodeSubnetIDs)
		if err != nil {
			m.logger.Warn("Unable to synchronize targeted Azure subnets for instance, falling back to full VNet discovery",
				logfields.Error, err, logfields.InstanceID, instanceID)
			vnets, subnets, err = m.api.GetVpcsAndSubnets(ctx)
			if err != nil {
				m.logger.Warn("Unable to synchronize Azure virtualnetworks list", logfields.Error, err)
				return time.Time{}
			}
		}
	} else {
		vnets, subnets, err = m.api.GetVpcsAndSubnets(ctx)
		if err != nil {
			m.logger.Warn("Unable to synchronize Azure virtualnetworks list", logfields.Error, err)
			return time.Time{}
		}
	}
	
	// Re-query instance with discovered subnets for complete information
	instance, err = m.api.GetInstance(ctx, subnets, instanceID)
	if err != nil {
		m.logger.Warn("Unable to synchronize Azure instance interface list with subnet information",
			logfields.Error, err,
			logfields.InstanceID, instanceID,
		)
		return time.Time{}
	}

	m.logger.Info(
		"Synchronized Azure IPAM information for the corresponding instance using targeted subnet discovery",
		logfields.InstanceID, instanceID,
		logfields.NumVirtualNetworks, len(vnets),
		logfields.NumSubnets, len(subnets),
		"targeted_subnets", len(nodeSubnetIDs),
	)

	m.mutex.Lock()
	defer m.mutex.Unlock()
	m.instances.UpdateInstance(instanceID, instance)
	m.vnets = vnets
	m.subnets = subnets

	return resyncStart
}

// extractSubnetIDs extracts unique subnet IDs from node network interfaces
func (m *InstancesManager) extractSubnetIDs(instances *ipamTypes.InstanceMap) []string {
	subnetIDs := make(map[string]bool)
	
	instances.ForeachAddress("", func(instanceID, interfaceID, ip, poolID string, address ipamTypes.Address) error {
		if poolID != "" {
			subnetIDs[poolID] = true
		}
		return nil
	})
	
	result := make([]string, 0, len(subnetIDs))
	for id := range subnetIDs {
		result = append(result, id)
	}
	return result
}

// resyncInstances performs a full sync of all instances using three-phase strategy
func (m *InstancesManager) resyncInstances(ctx context.Context) time.Time {
	resyncStart := time.Now()

	// Phase 1: Get all node instances (still using existing method as fallback)
	instances, err := m.api.GetInstances(ctx, ipamTypes.SubnetMap{})
	if err != nil {
		m.logger.Warn("Unable to synchronize Azure instances list", logfields.Error, err)
		return time.Time{}
	}
	
	// Phase 2: Extract subnet IDs from node interfaces
	nodeSubnetIDs := m.extractSubnetIDs(instances)
	
	// Phase 3: Query targeted subnets
	var vnets ipamTypes.VirtualNetworkMap
	var subnets ipamTypes.SubnetMap
	
	if len(nodeSubnetIDs) > 0 {
		vnets, subnets, err = m.api.GetNodesSubnets(ctx, nodeSubnetIDs)
		if err != nil {
			m.logger.Warn("Unable to synchronize targeted Azure subnets, falling back to full VNet discovery", logfields.Error, err)
			// Fallback to full VNet discovery if targeted approach fails
			vnets, subnets, err = m.api.GetVpcsAndSubnets(ctx)
			if err != nil {
				m.logger.Warn("Unable to synchronize Azure virtualnetworks list", logfields.Error, err)
				return time.Time{}
			}
		}
	} else {
		// No node subnets found, fallback to full discovery
		vnets, subnets, err = m.api.GetVpcsAndSubnets(ctx)
		if err != nil {
			m.logger.Warn("Unable to synchronize Azure virtualnetworks list", logfields.Error, err)
			return time.Time{}
		}
	}

	// Re-query instances with discovered subnets for complete information
	instances, err = m.api.GetInstances(ctx, subnets)
	if err != nil {
		m.logger.Warn("Unable to synchronize Azure instances list with subnet information", logfields.Error, err)
		return time.Time{}
	}

	m.logger.Info(
		"Synchronized Azure IPAM information using targeted subnet discovery",
		logfields.NumInstances, instances.NumInstances(),
		logfields.NumVirtualNetworks, len(vnets),
		logfields.NumSubnets, len(subnets),
		"targeted_subnets", len(nodeSubnetIDs),
	)

	m.mutex.Lock()
	defer m.mutex.Unlock()
	m.instances = instances
	m.vnets = vnets
	m.subnets = subnets

	return resyncStart
}

func (m *InstancesManager) InstanceSync(ctx context.Context, instanceID string) time.Time {
	// Instance incremental resync from different nodes should be executed in parallel,
	// but must block the full API resync.
	m.resyncLock.RLock()
	defer m.resyncLock.RUnlock()
	return m.resyncInstance(ctx, instanceID)
}

// DeleteInstance delete instance from m.instances
func (m *InstancesManager) DeleteInstance(instanceID string) {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	m.instances.Delete(instanceID)
}
