// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ipam

import (
	"context"

	"github.com/cilium/cilium/pkg/ipam"
	ipamTypes "github.com/cilium/cilium/pkg/ipam/types"
	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/time"
)

// AzureAPI is the API surface used of the Azure API
type AzureAPI interface {
	GetInstance(ctx context.Context, subnets ipamTypes.SubnetMap, instanceID string) (*ipamTypes.Instance, error)
	GetInstances(ctx context.Context, subnets ipamTypes.SubnetMap) (*ipamTypes.InstanceMap, error)
	GetVpcsAndSubnets(ctx context.Context) (ipamTypes.VirtualNetworkMap, ipamTypes.SubnetMap, error)
	AssignPrivateIpAddressesVM(ctx context.Context, subnetID, interfaceName string, addresses int) error
	AssignPrivateIpAddressesVMSS(ctx context.Context, instanceID, vmssName, subnetID, interfaceName string, addresses int) error
}

// InstancesManager maintains the list of instances. It must be kept up to date
// by calling Resync() regularly.
type InstancesManager struct {
	logger logging.FieldLogger
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
func NewInstancesManager(logger logging.FieldLogger, api AzureAPI) *InstancesManager {
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

	vnets, subnets, err := m.api.GetVpcsAndSubnets(ctx)
	if err != nil {
		m.logger.Warn("Unable to synchronize Azure virtualnetworks list", logfields.Error, err)
		return time.Time{}
	}

	instance, err := m.api.GetInstance(ctx, subnets, instanceID)
	if err != nil {
		m.logger.Warn("Unable to synchronize Azure instance interface list",
			logfields.Error, err,
			logfields.InstanceID, instanceID,
		)
		return time.Time{}
	}

	m.logger.Info(
		"Synchronized Azure IPAM information for the corresponding instance",
		logfields.InstanceID, instanceID,
		logfields.NumVirtualNetworks, len(vnets),
		logfields.NumSubnets, len(subnets),
	)

	m.mutex.Lock()
	defer m.mutex.Unlock()
	m.instances.UpdateInstance(instanceID, instance)
	m.vnets = vnets
	m.subnets = subnets

	return resyncStart
}

// resyncInstances performs a full sync of all instances
func (m *InstancesManager) resyncInstances(ctx context.Context) time.Time {
	resyncStart := time.Now()

	vnets, subnets, err := m.api.GetVpcsAndSubnets(ctx)
	if err != nil {
		m.logger.Warn("Unable to synchronize Azure virtualnetworks list", logfields.Error, err)
		return time.Time{}
	}

	instances, err := m.api.GetInstances(ctx, subnets)
	if err != nil {
		m.logger.Warn("Unable to synchronize Azure instances list", logfields.Error, err)
		return time.Time{}
	}

	m.logger.Info(
		"Synchronized Azure IPAM information",
		logfields.NumInstances, instances.NumInstances(),
		logfields.NumVirtualNetworks, len(vnets),
		logfields.NumSubnets, len(subnets),
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
