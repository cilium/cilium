// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package mock

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork/v8"
	"golang.org/x/time/rate"

	"github.com/cilium/cilium/pkg/api/helpers"
	"github.com/cilium/cilium/pkg/azure/types"
	"github.com/cilium/cilium/pkg/ipam/service/ipallocator"
	ipamTypes "github.com/cilium/cilium/pkg/ipam/types"
	"github.com/cilium/cilium/pkg/lock"
)

// Operation is an Azure API operation that this mock API supports
type Operation int

const (
	AllOperations Operation = iota
	GetInstance
	GetInstances
	GetVpcsAndSubnets
	GetSubnetsByIDs
	AssignPrivateIpAddressesVMSS
	MaxOperation
)

type subnet struct {
	subnet    *ipamTypes.Subnet
	allocator *ipallocator.Range
}

type API struct {
	mutex     lock.RWMutex
	subnets   map[string]*subnet
	instances *ipamTypes.InstanceMap
	vnets     map[string]*ipamTypes.VirtualNetwork
	errors    map[Operation]error
	delaySim  *helpers.DelaySimulator
	limiter   *rate.Limiter
}

func NewAPI(subnets []*ipamTypes.Subnet, vnets []*ipamTypes.VirtualNetwork) *API {
	api := &API{
		instances: ipamTypes.NewInstanceMap(),
		subnets:   map[string]*subnet{},
		vnets:     map[string]*ipamTypes.VirtualNetwork{},
		errors:    map[Operation]error{},
		delaySim:  helpers.NewDelaySimulator(),
	}

	api.UpdateSubnets(subnets)

	for _, v := range vnets {
		api.vnets[v.ID] = v
	}

	return api
}

func (a *API) UpdateSubnets(subnets []*ipamTypes.Subnet) {
	a.mutex.Lock()
	a.subnets = map[string]*subnet{}
	for _, s := range subnets {
		_, cidr, _ := net.ParseCIDR(s.CIDR.String())

		a.subnets[s.ID] = &subnet{
			subnet:    s.DeepCopy(),
			allocator: ipallocator.NewCIDRRange(cidr),
		}
	}
	a.mutex.Unlock()
}

func (a *API) UpdateInstances(instances *ipamTypes.InstanceMap) {
	a.mutex.Lock()
	a.updateInstancesLocked(instances)
	a.mutex.Unlock()
}

func (a *API) updateInstancesLocked(instances *ipamTypes.InstanceMap) {
	a.instances = instances.DeepCopy()
}

// SetMockError modifies the mock API to return an error for a particular
// operation
func (a *API) SetMockError(op Operation, err error) {
	a.mutex.Lock()
	a.errors[op] = err
	a.mutex.Unlock()
}

// SetDelay specifies the delay which should be simulated for an individual
// Azure API operation
func (a *API) SetDelay(op Operation, delay time.Duration) {
	if op == AllOperations {
		for op := AllOperations + 1; op < MaxOperation; op++ {
			a.delaySim.SetDelay(op, delay)
		}
	} else {
		a.delaySim.SetDelay(op, delay)
	}
}

// SetLimiter adds a rate limiter to all simulated API calls
func (a *API) SetLimiter(limit float64, burst int) {
	a.limiter = rate.NewLimiter(rate.Limit(limit), burst)
}

func (a *API) rateLimit() {
	a.mutex.RLock()
	if a.limiter == nil {
		a.mutex.RUnlock()
		return
	}

	r := a.limiter.Reserve()
	a.mutex.RUnlock()
	if delay := r.Delay(); delay != time.Duration(0) && delay != rate.InfDuration {
		time.Sleep(delay)
	}
}

func (a *API) GetInstance(ctx context.Context, subnets ipamTypes.SubnetMap, instanceID string) (*ipamTypes.Instance, error) {
	a.rateLimit()
	a.delaySim.Delay(GetInstance)

	a.mutex.RLock()
	defer a.mutex.RUnlock()

	if err, ok := a.errors[GetInstance]; ok {
		return nil, err
	}

	instance := ipamTypes.Instance{}
	instance.Interfaces = map[string]ipamTypes.InterfaceRevision{}
	if err := a.instances.ForeachInterface(instanceID, func(instanceID, interfaceID string, iface ipamTypes.InterfaceRevision) error {
		instance.Interfaces[interfaceID] = iface
		return nil
	}); err != nil {
		return nil, err
	}
	return instance.DeepCopy(), nil
}

func (a *API) GetInstances(ctx context.Context, subnets ipamTypes.SubnetMap) (*ipamTypes.InstanceMap, error) {
	a.rateLimit()
	a.delaySim.Delay(GetInstances)

	a.mutex.RLock()
	defer a.mutex.RUnlock()

	if err, ok := a.errors[GetInstances]; ok {
		return nil, err
	}

	return a.instances.DeepCopy(), nil
}

func (a *API) GetVpcsAndSubnets(ctx context.Context) (ipamTypes.VirtualNetworkMap, ipamTypes.SubnetMap, error) {
	a.rateLimit()
	a.delaySim.Delay(GetVpcsAndSubnets)

	a.mutex.RLock()
	defer a.mutex.RUnlock()

	if err, ok := a.errors[GetVpcsAndSubnets]; ok {
		return nil, nil, err
	}

	vnets := ipamTypes.VirtualNetworkMap{}
	subnets := ipamTypes.SubnetMap{}

	for _, s := range a.subnets {
		sd := s.subnet.DeepCopy()
		sd.AvailableAddresses = s.allocator.Free()
		subnets[sd.ID] = sd
	}

	for _, v := range a.vnets {
		vnets[v.ID] = v.DeepCopy()
	}

	return vnets, subnets, nil
}

func (a *API) GetSubnetsByIDs(ctx context.Context, nodeSubnetIDs []string) (ipamTypes.SubnetMap, error) {
	a.rateLimit()
	a.delaySim.Delay(GetSubnetsByIDs)

	a.mutex.RLock()
	defer a.mutex.RUnlock()

	if err, ok := a.errors[GetSubnetsByIDs]; ok {
		return nil, err
	}

	subnets := ipamTypes.SubnetMap{}

	// Only return subnets that match the requested subnet IDs
	subnetIDSet := make(map[string]struct{})
	for _, id := range nodeSubnetIDs {
		subnetIDSet[id] = struct{}{}
	}

	for _, s := range a.subnets {
		if _, exists := subnetIDSet[s.subnet.ID]; exists {
			sd := s.subnet.DeepCopy()
			sd.AvailableAddresses = s.allocator.Free()
			subnets[sd.ID] = sd
		}
	}

	return subnets, nil
}

func (a *API) AssignPrivateIpAddressesVM(ctx context.Context, subnetID, interfaceName string, addresses int) error {
	return nil
}

func (a *API) AssignPrivateIpAddressesVMSS(ctx context.Context, vmName, vmssName, subnetID, interfaceName string, addresses int) error {
	a.rateLimit()
	a.delaySim.Delay(AssignPrivateIpAddressesVMSS)

	a.mutex.Lock()
	defer a.mutex.Unlock()

	if err, ok := a.errors[AssignPrivateIpAddressesVMSS]; ok {
		return err
	}

	foundInterface := false
	instances := a.instances.DeepCopy()
	err := instances.ForeachInterface("", func(id, _ string, iface ipamTypes.InterfaceRevision) error {
		intf, ok := iface.Resource.(*types.AzureInterface)
		if !ok {
			return fmt.Errorf("invalid interface object")
		}

		if intf.Name != interfaceName || intf.GetVMID() != vmName {
			return nil
		}

		if len(intf.Addresses)+addresses > types.InterfaceAddressLimit {
			return fmt.Errorf("exceeded interface limit")
		}

		s, ok := a.subnets[subnetID]
		if !ok {
			return fmt.Errorf("subnet %s does not exist", subnetID)
		}

		for range addresses {
			ip, err := s.allocator.AllocateNext()
			if err != nil {
				panic("Unable to allocate IP from allocator")
			}
			intf.Addresses = append(intf.Addresses, types.AzureAddress{
				IP:     ip.String(),
				Subnet: subnetID,
				State:  types.StateSucceeded,
			})
		}

		foundInterface = true
		return nil
	})
	if err != nil {
		return err
	}

	a.updateInstancesLocked(instances)

	if !foundInterface {
		return fmt.Errorf("interface %s not found", interfaceName)
	}

	return nil
}

func (a *API) AssignPublicIPAddressesVMSS(ctx context.Context, instanceID, vmssName string, publicIpTags ipamTypes.Tags) (string, error) {
	a.rateLimit()
	return "mock-public-ip-prefix-id", nil
}

func (a *API) AssignPublicIPAddressesVM(ctx context.Context, instanceID string, publicIpTags ipamTypes.Tags) (string, error) {
	a.rateLimit()
	return "mock-public-ip-prefix-id", nil
}

// ListAllNetworkInterfaces returns a dummy slice since mock doesn't use real network interfaces
// The mock API uses instances directly rather than armnetwork.Interface objects
func (a *API) ListAllNetworkInterfaces(ctx context.Context) ([]*armnetwork.Interface, error) {
	a.rateLimit()
	a.delaySim.Delay(GetInstances)

	a.mutex.RLock()
	defer a.mutex.RUnlock()

	if err, ok := a.errors[GetInstances]; ok {
		return nil, err
	}

	// Return an empty slice - the mock doesn't use actual armnetwork.Interface objects
	// ParseInterfacesIntoInstanceMap will handle returning the mock instances
	return []*armnetwork.Interface{}, nil
}

// ParseInterfacesIntoInstanceMap ignores the input and returns the mock's instances
// The mock API doesn't use real armnetwork.Interface objects
func (a *API) ParseInterfacesIntoInstanceMap(networkInterfaces []*armnetwork.Interface, subnets ipamTypes.SubnetMap) *ipamTypes.InstanceMap {
	a.mutex.RLock()
	defer a.mutex.RUnlock()
	// Return the mock's instances regardless of input
	return a.instances.DeepCopy()
}

// ListVMNetworkInterfaces returns a dummy slice since mock doesn't use real network interfaces
// The mock API uses instances directly rather than armnetwork.Interface objects
func (a *API) ListVMNetworkInterfaces(ctx context.Context, instanceID string) ([]*armnetwork.Interface, error) {
	a.rateLimit()
	a.delaySim.Delay(GetInstance)

	a.mutex.RLock()
	defer a.mutex.RUnlock()

	if err, ok := a.errors[GetInstance]; ok {
		return nil, err
	}

	// Check if instance exists
	if !a.instances.Exists(instanceID) {
		return nil, fmt.Errorf("instance %s not found", instanceID)
	}

	// Return an empty slice - the mock doesn't use actual armnetwork.Interface objects
	// ParseInterfacesIntoInstance will handle returning the mock instance
	return []*armnetwork.Interface{}, nil
}

// ParseInterfacesIntoInstance ignores the input and returns the mock's instance
// The mock API doesn't use real armnetwork.Interface objects
func (a *API) ParseInterfacesIntoInstance(networkInterfaces []*armnetwork.Interface, subnets ipamTypes.SubnetMap) *ipamTypes.Instance {
	a.mutex.RLock()
	defer a.mutex.RUnlock()
	// The instance will be populated by the caller based on the mock's data
	// Return a basic structure that will be filled in
	return &ipamTypes.Instance{Interfaces: map[string]ipamTypes.InterfaceRevision{}}
}
