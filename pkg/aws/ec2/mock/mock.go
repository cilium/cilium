// Copyright 2019 Authors of Cilium
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

	"github.com/cilium/cilium/pkg/aws/types"
	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/uuid"

	"golang.org/x/time/rate"
	"k8s.io/kubernetes/pkg/registry/core/service/ipallocator"
)

type eniMap map[string]*v2.ENI

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

type API struct {
	mutex          lock.RWMutex
	unattached     map[string]*v2.ENI
	enis           map[string]eniMap
	subnets        map[string]*types.Subnet
	vpcs           map[string]*types.Vpc
	securityGroups map[string]*types.SecurityGroup
	errors         map[Operation]error
	delays         map[Operation]time.Duration
	allocator      *ipallocator.Range
	limiter        *rate.Limiter
}

func NewAPI(subnets []*types.Subnet, vpcs []*types.Vpc, securityGroups []*types.SecurityGroup) *API {
	_, cidr, _ := net.ParseCIDR("10.0.0.0/8")
	cidrRange, err := ipallocator.NewCIDRRange(cidr)
	if err != nil {
		panic(err)
	}

	api := &API{
		unattached:     map[string]*v2.ENI{},
		enis:           map[string]eniMap{},
		subnets:        map[string]*types.Subnet{},
		vpcs:           map[string]*types.Vpc{},
		securityGroups: map[string]*types.SecurityGroup{},
		allocator:      cidrRange,
		errors:         map[Operation]error{},
		delays:         map[Operation]time.Duration{},
	}

	for _, s := range subnets {
		api.subnets[s.ID] = s
	}

	for _, v := range vpcs {
		api.vpcs[v.ID] = v
	}

	for _, sg := range securityGroups {
		api.securityGroups[sg.ID] = sg
	}

	return api
}

// SetMockError modifies the mock API to return an error for a particular
// operation
func (e *API) SetMockError(op Operation, err error) {
	e.mutex.Lock()
	e.errors[op] = err
	e.mutex.Unlock()
}

func (e *API) setDelayLocked(op Operation, delay time.Duration) {
	if delay == time.Duration(0) {
		delete(e.delays, op)
	} else {
		e.delays[op] = delay
	}
}

// SetDelay specifies the delay which should be simulated for an individual EC2
// API operation
func (e *API) SetDelay(op Operation, delay time.Duration) {
	e.mutex.Lock()
	if op == AllOperations {
		for op := AllOperations + 1; op < MaxOperation; op++ {
			e.setDelayLocked(op, delay)
		}
	} else {
		e.setDelayLocked(op, delay)
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

func (e *API) simulateDelay(op Operation) {
	e.mutex.RLock()
	delay, ok := e.delays[op]
	e.mutex.RUnlock()
	if ok {
		time.Sleep(delay)
	}
}

func (e *API) CreateNetworkInterface(ctx context.Context, toAllocate int64, subnetID, desc string, groups []string) (string, *v2.ENI, error) {
	e.rateLimit()
	e.simulateDelay(CreateNetworkInterface)

	e.mutex.Lock()
	defer e.mutex.Unlock()

	if err, ok := e.errors[CreateNetworkInterface]; ok {
		return "", nil, err
	}

	subnet, ok := e.subnets[subnetID]
	if !ok {
		return "", nil, fmt.Errorf("subnet %s not found", subnetID)
	}

	if int(toAllocate) > subnet.AvailableAddresses {
		return "", nil, fmt.Errorf("subnet %s has not enough addresses available", subnetID)
	}

	eniID := uuid.NewUUID().String()
	eni := &v2.ENI{
		ID:          eniID,
		Description: desc,
		Subnet: v2.AwsSubnet{
			ID: subnetID,
		},
		SecurityGroups: groups,
	}

	for i := int64(0); i < toAllocate; i++ {
		ip, err := e.allocator.AllocateNext()
		if err != nil {
			panic("Unable to allocate IP from allocator")
		}
		eni.Addresses = append(eni.Addresses, ip.String())
	}

	subnet.AvailableAddresses -= int(toAllocate)

	e.unattached[eniID] = eni
	return eniID, eni, nil
}

func (e *API) DeleteNetworkInterface(ctx context.Context, eniID string) error {
	e.rateLimit()
	e.simulateDelay(DeleteNetworkInterface)

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

func (e *API) AttachNetworkInterface(ctx context.Context, index int64, instanceID, eniID string) (string, error) {
	e.rateLimit()
	e.simulateDelay(AttachNetworkInterface)

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
		e.enis[instanceID] = eniMap{}
	}

	eni.Number = int(index)

	e.enis[instanceID][eniID] = eni

	return "", nil
}

func (e *API) ModifyNetworkInterface(ctx context.Context, eniID, attachmentID string, deleteOnTermination bool) error {
	e.rateLimit()
	e.simulateDelay(ModifyNetworkInterface)

	e.mutex.Lock()
	defer e.mutex.Unlock()

	if err, ok := e.errors[ModifyNetworkInterface]; ok {
		return err
	}

	return nil
}

func (e *API) AssignPrivateIpAddresses(ctx context.Context, eniID string, addresses int64) error {
	e.rateLimit()
	e.simulateDelay(AssignPrivateIpAddresses)

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

			for i := int64(0); i < addresses; i++ {
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
	e.simulateDelay(UnassignPrivateIpAddresses)

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

func (e *API) GetInstances(ctx context.Context, vpcs types.VpcMap, subnets types.SubnetMap) (types.InstanceMap, error) {
	instances := types.InstanceMap{}

	e.mutex.RLock()
	defer e.mutex.RUnlock()

	for instanceID, enis := range e.enis {
		for _, eni := range enis {
			if subnets != nil {
				if subnet, ok := subnets[eni.Subnet.ID]; ok {
					eni.Subnet.CIDR = subnet.CIDR
				}
			}

			if vpcs != nil {
				if vpc, ok := vpcs[eni.VPC.ID]; ok {
					eni.VPC.PrimaryCIDR = vpc.PrimaryCIDR
				}
			}

			instances.Add(instanceID, eni)
		}
	}

	return instances, nil
}

func (e *API) GetVpcs(ctx context.Context) (types.VpcMap, error) {
	vpcs := types.VpcMap{}

	e.mutex.RLock()
	defer e.mutex.RUnlock()

	for _, v := range e.vpcs {
		vpcs[v.ID] = v
	}
	return vpcs, nil
}

func (e *API) GetSubnets(ctx context.Context) (types.SubnetMap, error) {
	subnets := types.SubnetMap{}

	e.mutex.RLock()
	defer e.mutex.RUnlock()

	for _, s := range e.subnets {
		subnets[s.ID] = s
	}
	return subnets, nil
}

func (e *API) TagENI(ctx context.Context, eniID string, eniTags map[string]string) error {
	e.rateLimit()
	e.simulateDelay(TagENI)

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
		securityGroups[sg.ID] = sg
	}
	return securityGroups, nil
}
