// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package mock

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/cilium/cilium/pkg/api/helpers"
	eniTypes "github.com/cilium/cilium/pkg/aws/eni/types"
	"github.com/cilium/cilium/pkg/aws/types"
	"github.com/cilium/cilium/pkg/ip"
	"github.com/cilium/cilium/pkg/ipam/cidrset"
	"github.com/cilium/cilium/pkg/ipam/option"
	"github.com/cilium/cilium/pkg/ipam/service/ipallocator"
	ipamTypes "github.com/cilium/cilium/pkg/ipam/types"
	"github.com/cilium/cilium/pkg/lock"

	"github.com/google/uuid"
	log "github.com/sirupsen/logrus"
	"golang.org/x/time/rate"
)

// ENIMap is a map of ENI interfaced indexed by ENI ID
type ENIMap map[string]*eniTypes.ENI

// Operation is an EC2 API operation that this mock API supports
type Operation int

const (
	AllOperations Operation = iota
	CreateNetworkInterface
	DeleteNetworkInterface
	AttachNetworkInterface
	ModifyNetworkInterface
	AssignPrivateIpAddresses
	UnassignPrivateIpAddresses
	TagENI
	MaxOperation
)

// API represents a mocked EC2 API
type API struct {
	mutex          lock.RWMutex
	unattached     map[string]*eniTypes.ENI
	enis           map[string]ENIMap
	subnets        map[string]*ipamTypes.Subnet
	vpcs           map[string]*ipamTypes.VirtualNetwork
	securityGroups map[string]*types.SecurityGroup
	errors         map[Operation]error
	allocator      *ipallocator.Range
	pdAllocator    *cidrset.CidrSet
	limiter        *rate.Limiter
	delaySim       *helpers.DelaySimulator
	pdSubnet       *net.IPNet
}

// NewAPI returns a new mocked EC2 API
func NewAPI(subnets []*ipamTypes.Subnet, vpcs []*ipamTypes.VirtualNetwork, securityGroups []*types.SecurityGroup) *API {

	// Start with base CIDR 10.0.0.0/16
	_, baseCidr, _ := net.ParseCIDR("10.10.0.0/16")

	// Use 10.10.0.0/17 for IP allocations
	cidrSet, _ := cidrset.NewCIDRSet(baseCidr, 17)
	podCidr, _ := cidrSet.AllocateNext()
	podCidrRange, err := ipallocator.NewCIDRRange(podCidr)
	if err != nil {
		panic(err)
	}
	// Use 10.10.128.0/17 for prefix allocations
	pdCidr, _ := cidrSet.AllocateNext()
	pdCidrRange, err := cidrset.NewCIDRSet(pdCidr, 28)
	if err != nil {
		panic(err)
	}

	api := &API{
		unattached:     map[string]*eniTypes.ENI{},
		enis:           map[string]ENIMap{},
		subnets:        map[string]*ipamTypes.Subnet{},
		vpcs:           map[string]*ipamTypes.VirtualNetwork{},
		securityGroups: map[string]*types.SecurityGroup{},
		allocator:      podCidrRange,
		pdAllocator:    pdCidrRange,
		errors:         map[Operation]error{},
		delaySim:       helpers.NewDelaySimulator(),
		pdSubnet:       pdCidr,
	}

	api.UpdateSubnets(subnets)
	api.UpdateSecurityGroups(securityGroups)

	for _, v := range vpcs {
		api.vpcs[v.ID] = v
	}

	return api
}

// UpdateSubnets replaces the subents which the mock API will return
func (e *API) UpdateSubnets(subnets []*ipamTypes.Subnet) {
	e.mutex.Lock()
	e.subnets = map[string]*ipamTypes.Subnet{}
	for _, s := range subnets {
		e.subnets[s.ID] = s.DeepCopy()
	}
	e.mutex.Unlock()
}

// UpdateSecurityGroups replaces the security groups which the mock API will return
func (e *API) UpdateSecurityGroups(securityGroups []*types.SecurityGroup) {
	e.mutex.Lock()
	e.securityGroups = map[string]*types.SecurityGroup{}
	for _, sg := range securityGroups {
		e.securityGroups[sg.ID] = sg.DeepCopy()
	}
	e.mutex.Unlock()
}

// UpdateENIs replaces the ENIs which the mock API will return
func (e *API) UpdateENIs(enis map[string]ENIMap) {
	e.mutex.Lock()
	e.enis = map[string]ENIMap{}
	for instanceID, m := range enis {
		e.enis[instanceID] = ENIMap{}
		for eniID, eni := range m {
			e.enis[instanceID][eniID] = eni.DeepCopy()
		}
	}
	e.mutex.Unlock()
}

// SetMockError modifies the mock API to return an error for a particular
// operation
func (e *API) SetMockError(op Operation, err error) {
	e.mutex.Lock()
	e.errors[op] = err
	e.mutex.Unlock()
}

// SetDelay specifies the delay which should be simulated for an individual EC2
// API operation
func (e *API) SetDelay(op Operation, delay time.Duration) {
	e.mutex.Lock()
	if op == AllOperations {
		for op := AllOperations + 1; op < MaxOperation; op++ {
			e.delaySim.SetDelay(op, delay)
		}
	} else {
		e.delaySim.SetDelay(op, delay)
	}
	e.mutex.Unlock()
}

// SetLimiter adds a rate limiter to all simulated API calls
func (e *API) SetLimiter(limit float64, burst int) {
	e.limiter = rate.NewLimiter(rate.Limit(limit), burst)
}

func (e *API) rateLimit() {
	e.mutex.RLock()
	if e.limiter == nil {
		e.mutex.RUnlock()
		return
	}

	r := e.limiter.Reserve()
	e.mutex.RUnlock()
	if delay := r.Delay(); delay != time.Duration(0) && delay != rate.InfDuration {
		time.Sleep(delay)
	}
}

// CreateNetworkInterface mocks the interface creation. As with the upstream
// EC2 API, the number of IP addresses in toAllocate are the number of
// secondary IPs, a primary IP is always allocated.
func (e *API) CreateNetworkInterface(ctx context.Context, toAllocate int32, subnetID, desc string, groups []string, allocatePrefixes bool) (string, *eniTypes.ENI, error) {
	e.rateLimit()
	e.delaySim.Delay(CreateNetworkInterface)

	e.mutex.Lock()
	defer e.mutex.Unlock()

	if err, ok := e.errors[CreateNetworkInterface]; ok {
		return "", nil, err
	}

	subnet, ok := e.subnets[subnetID]
	if !ok {
		return "", nil, fmt.Errorf("subnet %s not found", subnetID)
	}

	numAddresses := int(toAllocate) + 1 // include primary IP
	if numAddresses > subnet.AvailableAddresses {
		return "", nil, fmt.Errorf("subnet %s has not enough addresses available", subnetID)
	}

	eniID := uuid.New().String()
	eni := &eniTypes.ENI{
		ID:          eniID,
		Description: desc,
		Subnet: eniTypes.AwsSubnet{
			ID: subnetID,
		},
		SecurityGroups: groups,
	}

	primaryIP, err := e.allocator.AllocateNext()
	if err != nil {
		panic("Unable to allocate primary IP from allocator")
	}
	eni.IP = primaryIP.String()

	if allocatePrefixes {
		err := assignPrefixToENI(e, eni, int32(1))
		if err != nil {
			return "", nil, err
		}
	} else {
		for i := int32(0); i < toAllocate; i++ {
			ip, err := e.allocator.AllocateNext()
			if err != nil {
				panic("Unable to allocate IP from allocator")
			}
			eni.Addresses = append(eni.Addresses, ip.String())
		}
	}

	subnet.AvailableAddresses -= numAddresses

	e.unattached[eniID] = eni
	log.Debugf(" ENI after initial creation %v", eni)
	return eniID, eni.DeepCopy(), nil
}

func (e *API) DeleteNetworkInterface(ctx context.Context, eniID string) error {
	e.rateLimit()
	e.delaySim.Delay(DeleteNetworkInterface)

	e.mutex.Lock()
	defer e.mutex.Unlock()

	if err, ok := e.errors[DeleteNetworkInterface]; ok {
		return err
	}

	if _, ok := e.unattached[eniID]; ok {
		delete(e.unattached, eniID)
		return nil
	}

	for _, enis := range e.enis {
		if _, ok := enis[eniID]; ok {
			return fmt.Errorf("ENI ID %s is attached and cannot be deleted", eniID)
		}
	}

	return fmt.Errorf("ENI ID %s not found", eniID)
}

func (e *API) AttachNetworkInterface(ctx context.Context, index int32, instanceID, eniID string) (string, error) {
	e.rateLimit()
	e.delaySim.Delay(AttachNetworkInterface)

	e.mutex.Lock()
	defer e.mutex.Unlock()

	if err, ok := e.errors[AttachNetworkInterface]; ok {
		return "", err
	}

	eni, ok := e.unattached[eniID]
	if !ok {
		return "", fmt.Errorf("ENI ID %s does not exist", eniID)
	}

	delete(e.unattached, eniID)

	if _, ok := e.enis[instanceID]; !ok {
		e.enis[instanceID] = ENIMap{}
	}

	eni.Number = int(index)

	e.enis[instanceID][eniID] = eni

	return "", nil
}

func (e *API) DetachNetworkInterface(ctx context.Context, instanceID, eniID string) error {
	e.mutex.Lock()
	defer e.mutex.Unlock()

	if enis, ok := e.enis[instanceID]; ok {
		if eni, ok := enis[eniID]; ok {
			delete(e.enis[instanceID], eniID)
			e.unattached[eniID] = eni
			return nil
		}
	}

	return fmt.Errorf("ENI ID %s is not attached to instance %s", eniID, instanceID)
}

func (e *API) ModifyNetworkInterface(ctx context.Context, eniID, attachmentID string, deleteOnTermination bool) error {
	e.rateLimit()
	e.delaySim.Delay(ModifyNetworkInterface)

	e.mutex.Lock()
	defer e.mutex.Unlock()

	if err, ok := e.errors[ModifyNetworkInterface]; ok {
		return err
	}

	return nil
}

func (e *API) GetDetachedNetworkInterfaces(ctx context.Context, tags ipamTypes.Tags, maxResults int32) ([]string, error) {
	result := make([]string, 0, int(maxResults))
	for _, eni := range e.unattached {
		if ipamTypes.Tags(eni.Tags).Match(tags) {
			result = append(result, eni.ID)
		}

		if len(result) >= int(maxResults) {
			break
		}
	}
	return result, nil
}

func (e *API) AssignPrivateIpAddresses(ctx context.Context, eniID string, addresses int32) error {
	e.rateLimit()
	e.delaySim.Delay(AssignPrivateIpAddresses)

	e.mutex.Lock()
	defer e.mutex.Unlock()

	if err, ok := e.errors[AssignPrivateIpAddresses]; ok {
		return err
	}

	for _, enis := range e.enis {
		if eni, ok := enis[eniID]; ok {
			subnet, ok := e.subnets[eni.Subnet.ID]
			if !ok {
				return fmt.Errorf("subnet %s not found", eni.Subnet.ID)
			}

			if int(addresses) > subnet.AvailableAddresses {
				return fmt.Errorf("subnet %s has not enough addresses available", eni.Subnet.ID)
			}

			for i := int32(0); i < addresses; i++ {
				ip, err := e.allocator.AllocateNext()
				if err != nil {
					panic("Unable to allocate IP from allocator")
				}
				eni.Addresses = append(eni.Addresses, ip.String())
			}
			subnet.AvailableAddresses -= int(addresses)
			return nil
		}
	}
	return fmt.Errorf("Unable to find ENI with ID %s", eniID)
}

func (e *API) UnassignPrivateIpAddresses(ctx context.Context, eniID string, addresses []string) error {
	e.rateLimit()
	e.delaySim.Delay(UnassignPrivateIpAddresses)

	e.mutex.Lock()
	defer e.mutex.Unlock()

	if err, ok := e.errors[UnassignPrivateIpAddresses]; ok {
		return err
	}

	releaseMap := make(map[string]int)
	for _, addr := range addresses {
		// Validate given addresses
		ipaddr := net.ParseIP(addr)
		if ipaddr == nil {
			return fmt.Errorf("Invalid IP address %s", addr)
		}
		releaseMap[addr] = 0
	}

	for _, enis := range e.enis {
		eni, ok := enis[eniID]
		if !ok {
			continue
		}
		subnet, ok := e.subnets[eni.Subnet.ID]
		if !ok {
			return fmt.Errorf("subnet %s not found", eni.Subnet.ID)
		}

		addressesAfterRelease := []string{}

		for _, address := range eni.Addresses {
			_, ok := releaseMap[address]
			if !ok {
				addressesAfterRelease = append(addressesAfterRelease, address)
			} else {
				ip := net.ParseIP(address)
				e.allocator.Release(ip)
				subnet.AvailableAddresses++
			}
		}
		eni.Addresses = addressesAfterRelease
		return nil
	}
	return fmt.Errorf("Unable to find ENI with ID %s", eniID)
}

func assignPrefixToENI(e *API, eni *eniTypes.ENI, prefixes int32) error {
	subnet, ok := e.subnets[eni.Subnet.ID]
	if !ok {
		return fmt.Errorf("subnet %s not found", eni.Subnet.ID)
	}

	if int(prefixes)*option.ENIPDBlockSizeIPv4 > subnet.AvailableAddresses {
		return fmt.Errorf("subnet %s has not enough addresses available", eni.Subnet.ID)
	}

	for i := int32(0); i < prefixes; i++ {
		// Get a new /28 prefix
		pfx, err := e.pdAllocator.AllocateNext()
		if err != nil {
			return err
		}

		prefixStr := pfx.String()
		eni.Prefixes = append(eni.Prefixes, prefixStr)
		prefixIPs, err := ip.PrefixToIps(prefixStr)
		if err != nil {
			return fmt.Errorf("unable to convert prefix %s to ips", prefixStr)
		}
		eni.Addresses = append(eni.Addresses, prefixIPs...)
	}
	subnet.AvailableAddresses -= int(prefixes * option.ENIPDBlockSizeIPv4)
	return nil
}

func (e *API) AssignENIPrefixes(ctx context.Context, eniID string, prefixes int32) error {
	e.rateLimit()
	e.delaySim.Delay(AssignPrivateIpAddresses)

	e.mutex.Lock()
	defer e.mutex.Unlock()

	if err, ok := e.errors[AssignPrivateIpAddresses]; ok {
		return err
	}

	for _, enis := range e.enis {
		if eni, ok := enis[eniID]; ok {
			return assignPrefixToENI(e, eni, prefixes)
		}
	}
	return fmt.Errorf("Unable to find ENI with ID %s", eniID)
}

func (e *API) UnassignENIPrefixes(ctx context.Context, eniID string, prefixes []string) error {
	e.rateLimit()
	e.delaySim.Delay(UnassignPrivateIpAddresses)

	e.mutex.Lock()
	defer e.mutex.Unlock()

	if err, ok := e.errors[UnassignPrivateIpAddresses]; ok {
		return err
	}

	addresses := make([]string, 0)
	// Convert prefixes to IP addresses and release prefix from pd allocator
	for _, prefix := range prefixes {
		_, ipNet, err := net.ParseCIDR(prefix)
		if err != nil {
			return fmt.Errorf("Invalid CIDR block %s", prefix)
		}
		e.pdAllocator.Release(ipNet)
		ips, _ := ip.PrefixToIps(prefix)
		addresses = append(addresses, ips...)
	}

	releaseMap := make(map[string]int)
	for _, addr := range addresses {
		// Validate given addresses
		ipaddr := net.ParseIP(addr)
		if ipaddr == nil {
			return fmt.Errorf("Invalid IP address %s", addr)
		}
		releaseMap[addr] = 1
	}

	for _, enis := range e.enis {
		eni, ok := enis[eniID]
		if !ok {
			continue
		}
		subnet, ok := e.subnets[eni.Subnet.ID]
		if !ok {
			return fmt.Errorf("subnet %s not found", eni.Subnet.ID)
		}

		var addressesAfterRelease []string

		for _, address := range eni.Addresses {
			_, ok := releaseMap[address]
			if !ok {
				addressesAfterRelease = append(addressesAfterRelease, address)
			} else {
				subnet.AvailableAddresses++
			}
		}
		eni.Addresses = addressesAfterRelease
		return nil
	}
	return fmt.Errorf("Unable to find ENI with ID %s", eniID)
}

func (e *API) GetInstances(ctx context.Context, vpcs ipamTypes.VirtualNetworkMap, subnets ipamTypes.SubnetMap) (*ipamTypes.InstanceMap, error) {
	instances := ipamTypes.NewInstanceMap()

	e.mutex.RLock()
	defer e.mutex.RUnlock()

	for instanceID, enis := range e.enis {
		for _, eni := range enis {
			if subnets != nil {
				if subnet, ok := subnets[eni.Subnet.ID]; ok && subnet.CIDR != nil {
					eni.Subnet.CIDR = subnet.CIDR.String()
				}
			}

			if vpcs != nil {
				if vpc, ok := vpcs[eni.VPC.ID]; ok {
					eni.VPC.PrimaryCIDR = vpc.PrimaryCIDR
					eni.VPC.CIDRs = vpc.CIDRs
				}
			}

			eniRevision := ipamTypes.InterfaceRevision{Resource: eni.DeepCopy()}
			instances.Update(instanceID, eniRevision)
		}
	}

	return instances, nil
}

func (e *API) GetVpcs(ctx context.Context) (ipamTypes.VirtualNetworkMap, error) {
	vpcs := ipamTypes.VirtualNetworkMap{}

	e.mutex.RLock()
	defer e.mutex.RUnlock()

	for _, v := range e.vpcs {
		vpcs[v.ID] = v.DeepCopy()
	}
	return vpcs, nil
}

func (e *API) GetSubnets(ctx context.Context) (ipamTypes.SubnetMap, error) {
	subnets := ipamTypes.SubnetMap{}

	e.mutex.RLock()
	defer e.mutex.RUnlock()

	for _, s := range e.subnets {
		subnets[s.ID] = s.DeepCopy()
	}
	return subnets, nil
}

func (e *API) TagENI(ctx context.Context, eniID string, eniTags map[string]string) error {
	e.rateLimit()
	e.delaySim.Delay(TagENI)

	e.mutex.Lock()
	defer e.mutex.Unlock()

	if err, ok := e.errors[TagENI]; ok {
		return err
	}

	if eni, ok := e.unattached[eniID]; ok {
		eni.Tags = eniTags
		return nil
	}

	for _, enis := range e.enis {
		if eni, ok := enis[eniID]; ok {
			eni.Tags = eniTags
			return nil
		}
	}
	return fmt.Errorf("Unable to find ENI with ID %s", eniID)
}

func (e *API) GetSecurityGroups(ctx context.Context) (types.SecurityGroupMap, error) {
	securityGroups := types.SecurityGroupMap{}

	e.mutex.RLock()
	defer e.mutex.RUnlock()

	for _, sg := range e.securityGroups {
		securityGroups[sg.ID] = sg.DeepCopy()
	}
	return securityGroups, nil
}
