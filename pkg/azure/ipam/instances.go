// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ipam

import (
	"context"

	"github.com/sirupsen/logrus"

	"github.com/cilium/cilium/pkg/ipam"
	ipamTypes "github.com/cilium/cilium/pkg/ipam/types"
	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/time"
)

// AzureAPI is the API surface used of the Azure API
type AzureAPI interface {
	GetInstances(ctx context.Context, subnets ipamTypes.SubnetMap) (*ipamTypes.InstanceMap, error)
	GetNodesSubnets(ctx context.Context, subnetIDs []string) (ipamTypes.SubnetMap, error)
	AssignPrivateIpAddressesVM(ctx context.Context, subnetID, interfaceName string, addresses int) error
	AssignPrivateIpAddressesVMSS(ctx context.Context, instanceID, vmssName, subnetID, interfaceName string, addresses int) error
}

// InstancesManager maintains the list of instances. It must be kept up to date
// by calling resync() regularly.
type InstancesManager struct {
	mutex     lock.RWMutex
	instances *ipamTypes.InstanceMap
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

// extractSubnetIDs extracts unique subnet IDs from instance interfaces
func (m *InstancesManager) extractSubnetIDs(instances *ipamTypes.InstanceMap) []string {
	subnetIDs := make(map[string]struct{})

	instances.ForeachAddress("", func(instanceID, interfaceID, ip, poolID string, addressObj ipamTypes.Address) error {
		if poolID != "" {
			subnetIDs[poolID] = struct{}{}
		}
		return nil
	})

	result := make([]string, 0, len(subnetIDs))
	for subnetID := range subnetIDs {
		result = append(result, subnetID)
	}

	return result
}

// Resync fetches the list of Azure instances and subnets and updates the local
// cache in the instanceManager. It returns the time when the resync has
// started or time.Time{} if it did not complete.
func (m *InstancesManager) Resync(ctx context.Context) time.Time {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	resyncStart := time.Now()

	// Phase 1: Get instances to discover which subnets are actually in use
	// This provides subnet IDs without requiring subnet details upfront
	instances, err := m.api.GetInstances(ctx, ipamTypes.SubnetMap{})
	if err != nil {
		log.WithError(err).Warning("Unable to synchronize Azure instances list")
		return time.Time{}
	}

	// Extract subnet IDs from the instances we found
	subnetIDs := m.extractSubnetIDs(instances)

	// Phase 2: Query only the specific subnets that are actually used
	subnets, err := m.api.GetNodesSubnets(ctx, subnetIDs)
	if err != nil {
		log.WithError(err).Warning("Unable to synchronize Azure subnets list")
		// Continue with empty subnets map rather than failing completely
		subnets = ipamTypes.SubnetMap{}
	}

	// Phase 3: Re-parse instances with subnet details to populate CIDR and gateway info
	if len(subnets) > 0 {
		instances, err = m.api.GetInstances(ctx, subnets)
		if err != nil {
			log.WithError(err).Warning("Unable to re-synchronize Azure instances with subnet details")
			return time.Time{}
		}
	}

	log.WithFields(logrus.Fields{
		"numInstances": instances.NumInstances(),
		"numSubnets":   len(subnets),
		"subnetIDs":    subnetIDs,
	}).Info("Synchronized Azure IPAM information")

	m.instances = instances
	m.subnets = subnets

	return resyncStart
}

func (m *InstancesManager) InstanceSync(ctx context.Context, instanceID string) time.Time {
	// Resync for a separate instance is not implemented yet, fallback to full resync.
	return m.Resync(ctx)
}

// DeleteInstance delete instance from m.instances
func (m *InstancesManager) DeleteInstance(instanceID string) {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	m.instances.Delete(instanceID)
}
