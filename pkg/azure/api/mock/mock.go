// Copyright 2020 Authors of Cilium
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
	"github.com/cilium/cilium/pkg/azure/types"
	ipamTypes "github.com/cilium/cilium/pkg/ipam/types"
	"github.com/cilium/cilium/pkg/lock"

	"golang.org/x/time/rate"
)

// Operation is an Azure API operation that this mock API supports
type Operation int

const (
	AllOperations Operation = iota
	GetInstances
	GetVpcsAndSubnets
	AssignPrivateIpAddresses
	MaxOperation
)

type API struct {
	mutex     lock.RWMutex
	subnets   map[string]*ipamTypes.Subnet
	instances types.InstanceMap
	vnets     map[string]*ipamTypes.VirtualNetwork
	errors    map[Operation]error
	delaySim  *helpers.DelaySimulator
	limiter   *rate.Limiter
}

func NewAPI(subnets []*ipamTypes.Subnet, vnets []*ipamTypes.VirtualNetwork) *API {
	api := &API{
		instances: types.InstanceMap{},
		subnets:   map[string]*ipamTypes.Subnet{},
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
	a.subnets = map[string]*ipamTypes.Subnet{}
	for _, s := range subnets {
		a.subnets[s.ID] = s.DeepCopy()
	}
	a.mutex.Unlock()
}

func (a *API) UpdateInstances(instances types.InstanceMap) {
	a.mutex.Lock()
	a.instances = instances.DeepCopy()
	a.mutex.Unlock()
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

func (a *API) GetInstances(ctx context.Context) (types.InstanceMap, error) {
	a.rateLimit()
	a.delaySim.Delay(GetInstances)

	a.mutex.RLock()
	defer a.mutex.RUnlock()

	if err, ok := a.errors[GetInstances]; ok {
		return nil, err
	}

	instances := types.InstanceMap{}

	for instanceID, instance := range a.instances {
		for _, intf := range instance.Interfaces {
			instances.Update(instanceID, intf.DeepCopy())
		}
	}

	return instances, nil
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
		subnets[s.ID] = s.DeepCopy()
	}

	for _, v := range a.vnets {
		vnets[v.ID] = v.DeepCopy()
	}

	return vnets, subnets, nil
}

func (a *API) AssignPrivateIpAddresses(ctx context.Context, subnetID, interfaceID string, ips []net.IP) error {
	a.rateLimit()
	a.delaySim.Delay(AssignPrivateIpAddresses)

	a.mutex.Lock()
	defer a.mutex.Unlock()

	if err, ok := a.errors[AssignPrivateIpAddresses]; ok {
		return err
	}

	for _, instance := range a.instances {
		for _, intf := range instance.Interfaces {
			if intf.ID == interfaceID {
				if len(intf.Addresses)+len(ips) > types.InterfaceAddressLimit {
					return fmt.Errorf("exceeded interface limit")
				}

				for _, ip := range ips {
					intf.Addresses = append(intf.Addresses, types.AzureAddress{
						IP:     ip.String(),
						Subnet: subnetID,
						State:  types.StateSucceeded,
					})
				}

				return nil
			}
		}
	}

	return fmt.Errorf("interface %s not found", interfaceID)
}
