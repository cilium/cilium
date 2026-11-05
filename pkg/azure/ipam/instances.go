// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ipam

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"net/http"
	"net/netip"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork/v12"
	"k8s.io/apimachinery/pkg/util/sets"

	"github.com/cilium/cilium/operator/pkg/ipam/nodemanager"
	"github.com/cilium/cilium/pkg/azure/types"

	// Registers the Azure resource-ID parser used by AzureInterface's VMSS/VM
	// getters.
	_ "github.com/cilium/cilium/pkg/azure/types/azureid"
	"github.com/cilium/cilium/pkg/ipam/instances"
	ipamTypes "github.com/cilium/cilium/pkg/ipam/types"
	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/time"
)

// AzureAPI is the API surface used of the Azure API.
type AzureAPI interface {
	GetSubnetsByIDs(ctx context.Context, nodeSubnetIDs []string) (ipamTypes.SubnetMap, error)
	AssignPrivateIpAddressesVM(ctx context.Context, subnetID, interfaceName string, addresses int) error
	AssignPrivateIpAddressesVMSS(ctx context.Context, instanceID, vmssName, subnetID, interfaceName string, addresses int) error
	AssignPublicIPAddressesVM(ctx context.Context, instanceID string, publicIpTags ipamTypes.Tags) (netip.Addr, error)
	AssignPublicIPAddressesVMSS(ctx context.Context, instanceID, vmssName string, publicIpTags ipamTypes.Tags) (netip.Addr, error)
	ListAllNetworkInterfaces(ctx context.Context) ([]*armnetwork.Interface, error)
	ParseInterfacesIntoInstanceMap(networkInterfaces []*armnetwork.Interface, subnets ipamTypes.SubnetMap) *ipamTypes.InstanceMap
	ListVMNetworkInterfaces(ctx context.Context, instanceID string) ([]*armnetwork.Interface, error)
	ParseInterfacesIntoInstance(networkInterfaces []*armnetwork.Interface, subnets ipamTypes.SubnetMap) *ipamTypes.Instance
}

// InstancesManager maintains the list of instances. It must be kept up to date
// by calling Resync() regularly.
type InstancesManager struct {
	// InstanceCache caches the instances and owns the locks; the fields
	// below marked as protected by the cache lock are read and written
	// through its Read and resync publish functions.
	*instances.InstanceCache

	logger *slog.Logger

	// usePrimary mirrors the --azure-use-primary-address operator flag; when
	// true, each NIC's primary IP is exposed to the allocatable pool.
	usePrimary bool

	// subnets is protected by the cache lock.
	subnets ipamTypes.SubnetMap
	api     AzureAPI
}

// NewInstancesManager returns a new instances manager
func NewInstancesManager(logger *slog.Logger, api AzureAPI, usePrimary bool) *InstancesManager {
	return &InstancesManager{
		InstanceCache: instances.NewInstanceCache(),
		logger:        logger.With(subsysLogAttr...),
		api:           api,
		usePrimary:    usePrimary,
	}
}

// CreateNode is called on discovery of a new node
func (m *InstancesManager) CreateNode(obj *v2.CiliumNode, _ *nodemanager.Node) nodemanager.NodeOperations {
	return &Node{manager: m, instanceID: obj.InstanceID()}
}

// HasInstance and DeleteInstance are provided by the embedded InstanceCache.

// GetPoolQuota returns the number of available IPs in all IP pools
func (m *InstancesManager) GetPoolQuota() (quota ipamTypes.PoolQuotaMap) {
	pool := ipamTypes.PoolQuotaMap{}
	m.Read(func(_ *ipamTypes.InstanceMap) {
		for subnetID, subnet := range m.subnets {
			pool[ipamTypes.PoolID(subnetID)] = ipamTypes.PoolQuota{
				AvailableIPs: subnet.AvailableAddresses,
			}
		}
	})
	return pool
}

// Resync fetches the list of instances and subnets and updates the local
// cache in the instanceManager. It returns the time when the resync has
// started or an error if it did not complete.
func (m *InstancesManager) Resync(ctx context.Context) (time.Time, error) {
	return m.FullResync(ctx, m.fetchInstances)
}

// fetchInstance fetches a single instance and the subnets it uses. The
// returned publish function merges the fetched subnets into the cached ones.
func (m *InstancesManager) fetchInstance(ctx context.Context, instanceID string) (*ipamTypes.Instance, instances.PublishFunc, error) {
	// Fetch network interfaces once from Azure API
	networkInterfaces, err := m.api.ListVMNetworkInterfaces(ctx, instanceID)
	if err != nil {
		// A 404 from the Azure API is treated as the instance no longer
		// existing, so that callers can tell an instance that is gone
		// apart from a transient synchronization failure.
		var respErr *azcore.ResponseError
		if errors.As(err, &respErr) && respErr.StatusCode == http.StatusNotFound {
			return nil, nil, fmt.Errorf("%w: synchronize Azure instance %s interface list: %w", nodemanager.ErrInstanceNotFound, instanceID, err)
		}
		return nil, nil, fmt.Errorf("synchronize Azure instance %s interface list: %w", instanceID, err)
	}

	// Parse with empty subnets to discover which subnets are actually in use
	instance := m.api.ParseInterfacesIntoInstance(networkInterfaces, ipamTypes.SubnetMap{})
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

	// Re-parse the same network interface data with subnet details to populate
	// CIDR and gateway info without making another Azure API call
	if len(subnets) > 0 {
		instance = m.api.ParseInterfacesIntoInstance(networkInterfaces, subnets)
	}

	m.logger.Info(
		"Synchronized Azure IPAM information for the corresponding instance using targeted subnet discovery",
		logfields.InstanceID, instanceID,
		logfields.NumSubnets, len(subnets),
		logfields.TargetedSubnets, len(nodeSubnetIDs),
	)

	return instance, func() {
		if m.subnets == nil {
			m.subnets = ipamTypes.SubnetMap{}
		}
		maps.Copy(m.subnets, subnets)
	}, nil
}

// extractSubnetIDs extracts unique subnet IDs from node network interfaces
func (m *InstancesManager) extractSubnetIDs(instances *ipamTypes.InstanceMap) []string {
	subnetIDs := sets.New[string]()

	instances.ForeachInterface("", func(instanceID, interfaceID string, iface ipamTypes.Interface) error {
		if azIface, ok := iface.(*types.AzureInterface); ok && azIface.Subnet.ID != "" {
			subnetIDs.Insert(azIface.Subnet.ID)
		}
		return nil
	})

	return subnetIDs.UnsortedList()
}

// fetchInstances performs a full sync of all instances using three-phase strategy
// Optimization: Fetches network interfaces once from Azure, then parses them twice
func (m *InstancesManager) fetchInstances(ctx context.Context) (*ipamTypes.InstanceMap, instances.PublishFunc, error) {
	// Phase 1: Fetch network interfaces once from Azure API
	networkInterfaces, err := m.api.ListAllNetworkInterfaces(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("fetch Azure network interfaces: %w", err)
	}

	// Phase 2: Parse with empty subnets to discover which subnets are actually in use
	// This parsing is fast (in-memory operation, no Azure API call)
	instanceMap := m.api.ParseInterfacesIntoInstanceMap(networkInterfaces, ipamTypes.SubnetMap{})

	// Extract subnet IDs from the instances we found
	subnetIDs := m.extractSubnetIDs(instanceMap)

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
		instanceMap = m.api.ParseInterfacesIntoInstanceMap(networkInterfaces, subnets)
	}

	m.logger.Info(
		"Synchronized Azure IPAM information using targeted subnet discovery",
		logfields.NumInstances, instanceMap.NumInstances(),
		logfields.NumSubnets, len(subnets),
		logfields.TargetedSubnets, len(subnetIDs),
	)

	return instanceMap, func() {
		m.subnets = subnets
	}, nil
}

func (m *InstancesManager) InstanceSync(ctx context.Context, instanceID string) (time.Time, error) {
	return m.InstanceCache.InstanceSync(ctx, instanceID, func(ctx context.Context) (*ipamTypes.Instance, instances.PublishFunc, error) {
		return m.fetchInstance(ctx, instanceID)
	})
}
