// Copyright 2019-2020 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package mock

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/cilium/cilium/pkg/api/helpers"
	eniTypes "github.com/cilium/cilium/pkg/aws/eni/types"
	"github.com/cilium/cilium/pkg/aws/types"
	ipamTypes "github.com/cilium/cilium/pkg/ipam/types"
	"github.com/cilium/cilium/pkg/lock"

	"github.com/cilium/ipam/service/ipallocator"
	"github.com/google/uuid"
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
	limiter        *rate.Limiter
	delaySim       *helpers.DelaySimulator
}

// NewAPI returns a new mocked EC2 API
func NewAPI(subnets []*ipamTypes.Subnet, vpcs []*ipamTypes.VirtualNetwork, securityGroups []*types.SecurityGroup) *API {
	_, cidr, _ := net.ParseCIDR("10.0.0.0/8")
	cidrRange, err := ipallocator.NewCIDRRange(cidr)
	if err != nil {
		panic(err)
	}

	api := &API{
		unattached:     map[string]*eniTypes.ENI{},
		enis:           map[string]ENIMap{},
		subnets:        map[string]*ipamTypes.Subnet{},
		vpcs:           map[string]*ipamTypes.VirtualNetwork{},
		securityGroups: map[string]*types.SecurityGroup{},
		allocator:      cidrRange,
		errors:         map[Operation]error{},
		delaySim:       helpers.NewDelaySimulator(),
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
func (e *API) CreateNetworkInterface(ctx context.Context, toAllocate int32, subnetID, desc string, groups []string) (string, *eniTypes.ENI, error) {
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

	for i := int32(0); i < toAllocate; i++ {
		ip, err := e.allocator.AllocateNext()
		if err != nil {
			panic("Unable to allocate IP from allocator")
		}
		eni.Addresses = append(eni.Addresses, ip.String())
	}
	subnet.AvailableAddresses -= numAddresses

	e.unattached[eniID] = eni
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

	delete(e.unattached, eniID)
	for _, enis := range e.enis {
		if _, ok := enis[eniID]; ok {
			delete(enis, eniID)
			return nil
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

	e.mutex.RLock()
	defer e.mutex.RUnlock()

	if err, ok := e.errors[TagENI]; ok {
		return err
	}

	return nil
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
