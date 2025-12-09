// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ipam

import (
	"context"
	"log/slog"
	"maps"
	"slices"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork/v8"

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
	GetSubnetsByIDs(ctx context.Context, nodeSubnetIDs []string) (ipamTypes.SubnetMap, error)
	AssignPrivateIpAddressesVM(ctx context.Context, subnetID, interfaceName string, addresses int) error
	AssignPrivateIpAddressesVMSS(ctx context.Context, instanceID, vmssName, subnetID, interfaceName string, addresses int) error
	AssignPublicIPAddressesVM(ctx context.Context, instanceID string, publicIpTags ipamTypes.Tags) (string, error)
	AssignPublicIPAddressesVMSS(ctx context.Context, instanceID, vmssName string, publicIpTags ipamTypes.Tags) (string, error)
	// New methods for optimization: fetch network interfaces once and parse multiple times
	ListAllNetworkInterfaces(ctx context.Context) ([]*armnetwork.Interface, error)
	ParseInterfacesIntoInstanceMap(networkInterfaces []*armnetwork.Interface, subnets ipamTypes.SubnetMap) *ipamTypes.InstanceMap
	ListVMNetworkInterfaces(ctx context.Context, instanceID string) ([]*armnetwork.Interface, error)
	ParseInterfacesIntoInstance(networkInterfaces []*armnetwork.Interface, subnets ipamTypes.SubnetMap) *ipamTypes.Instance
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
// Note: This function uses GetInstance directly (not optimized with separate fetch/parse)
// because it already queries per-instance APIs which are relatively lightweight
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

	// Query targeted subnets
	subnets, err := m.api.GetSubnetsByIDs(ctx, nodeSubnetIDs)
	if err != nil {
		m.logger.Warn("Unable to synchronize Azure subnets list for instance",
			logfields.Error, err,
			logfields.InstanceID, instanceID,
		)
		// Continue with empty subnets map rather than failing completely
		subnets = ipamTypes.SubnetMap{}
	}

	// Re-query instance with discovered subnets for complete information
	if len(subnets) > 0 {
		instance, err = m.api.GetInstance(ctx, subnets, instanceID)
		if err != nil {
			m.logger.Warn("Unable to re-synchronize Azure instance with subnet details",
				logfields.Error, err,
				logfields.InstanceID, instanceID,
			)
			return time.Time{}
		}
	}

	m.logger.Info(
		"Synchronized Azure IPAM information for the corresponding instance using targeted subnet discovery",
		logfields.InstanceID, instanceID,
		logfields.NumSubnets, len(subnets),
		logfields.TargetedSubnets, len(nodeSubnetIDs),
	)

	m.mutex.Lock()
	defer m.mutex.Unlock()
	m.instances.UpdateInstance(instanceID, instance)
	m.subnets = subnets

	return resyncStart
}

// extractSubnetIDs extracts unique subnet IDs from node network interfaces
func (m *InstancesManager) extractSubnetIDs(instances *ipamTypes.InstanceMap) []string {
	// Use map[string]struct{} as a set for efficient deduplication (O(1) insertion, zero memory overhead)
	subnetIDs := make(map[string]struct{})

	instances.ForeachAddress("", func(instanceID, interfaceID, ip, poolID string, address ipamTypes.Address) error {
		if poolID != "" {
			subnetIDs[poolID] = struct{}{}
		}
		return nil
	})

	return slices.Collect(maps.Keys(subnetIDs))
}

// resyncInstances performs a full sync of all instances using three-phase strategy
// Optimization: Fetches network interfaces once from Azure, then parses them twice
func (m *InstancesManager) resyncInstances(ctx context.Context) time.Time {
	resyncStart := time.Now()

	// Phase 1: Fetch network interfaces once from Azure API
	networkInterfaces, err := m.api.ListAllNetworkInterfaces(ctx)
	if err != nil {
		m.logger.Warn("Unable to fetch Azure network interfaces", logfields.Error, err)
		return time.Time{}
	}

	// Phase 2: Parse with empty subnets to discover which subnets are actually in use
	// This parsing is fast (in-memory operation, no Azure API call)
	instances := m.api.ParseInterfacesIntoInstanceMap(networkInterfaces, ipamTypes.SubnetMap{})

	// Extract subnet IDs from the instances we found
	subnetIDs := m.extractSubnetIDs(instances)

	// Phase 3: Query only the specific subnets that are actually used
	subnets, err := m.api.GetSubnetsByIDs(ctx, subnetIDs)
	if err != nil {
		m.logger.Warn("Unable to synchronize Azure subnets list", logfields.Error, err)
		// Continue with empty subnets map rather than failing completely
		subnets = ipamTypes.SubnetMap{}
	}

	// Phase 4: Re-parse the SAME network interface data with subnet details
	// This populates CIDR and gateway info without making another Azure API call
	if len(subnets) > 0 {
		instances = m.api.ParseInterfacesIntoInstanceMap(networkInterfaces, subnets)
	}

	m.logger.Info(
		"Synchronized Azure IPAM information using targeted subnet discovery",
		logfields.NumInstances, instances.NumInstances(),
		logfields.NumSubnets, len(subnets),
		logfields.TargetedSubnets, len(subnetIDs),
	)

	m.mutex.Lock()
	defer m.mutex.Unlock()
	m.instances = instances
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
