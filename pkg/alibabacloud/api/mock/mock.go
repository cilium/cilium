// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package mock

import (
	"context"
	"fmt"
	"net"

	"github.com/google/uuid"

	eniTypes "github.com/cilium/cilium/pkg/alibabacloud/eni/types"
	"github.com/cilium/cilium/pkg/alibabacloud/types"
	"github.com/cilium/cilium/pkg/ipam/service/ipallocator"
	ipamTypes "github.com/cilium/cilium/pkg/ipam/types"
	"github.com/cilium/cilium/pkg/lock"
)

// ENIMap is a map of ENI interfaced indexed by ENI ID
type ENIMap map[string]*eniTypes.ENI

type API struct {
	mutex          lock.RWMutex
	unattached     map[string]*eniTypes.ENI
	enis           map[string]ENIMap
	subnets        map[string]*ipamTypes.Subnet
	vpcs           map[string]*ipamTypes.VirtualNetwork
	securityGroups map[string]*types.SecurityGroup
	allocator      *ipallocator.Range
}

// NewAPI returns a new mocked ECS API
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
	}

	api.UpdateSubnets(subnets)
	api.UpdateSecurityGroups(securityGroups)

	for _, v := range vpcs {
		api.vpcs[v.ID] = v
	}

	return api
}

// UpdateSubnets replaces the subents which the mock API will return
func (a *API) UpdateSubnets(subnets []*ipamTypes.Subnet) {
	a.mutex.Lock()
	defer a.mutex.Unlock()
	a.subnets = map[string]*ipamTypes.Subnet{}
	for _, s := range subnets {
		a.subnets[s.ID] = s.DeepCopy()
	}
}

// UpdateSecurityGroups replaces the security groups which the mock API will return
func (a *API) UpdateSecurityGroups(securityGroups []*types.SecurityGroup) {
	a.mutex.Lock()
	defer a.mutex.Unlock()
	a.securityGroups = map[string]*types.SecurityGroup{}
	for _, sg := range securityGroups {
		a.securityGroups[sg.ID] = sg.DeepCopy()
	}
}

// UpdateENIs replaces the ENIs which the mock API will return
func (a *API) UpdateENIs(enis map[string]ENIMap) {
	a.mutex.Lock()
	a.enis = map[string]ENIMap{}
	for instanceID, m := range enis {
		a.enis[instanceID] = ENIMap{}
		for eniID, eni := range m {
			a.enis[instanceID][eniID] = eni.DeepCopy()
		}
	}
	a.mutex.Unlock()
}

func (a *API) GetInstances(ctx context.Context, vpcs ipamTypes.VirtualNetworkMap, subnets ipamTypes.SubnetMap) (*ipamTypes.InstanceMap, error) {
	instances := ipamTypes.NewInstanceMap()

	a.mutex.RLock()
	defer a.mutex.RUnlock()

	for instanceID, enis := range a.enis {
		for _, eni := range enis {
			if subnets != nil {
				if subnet, ok := subnets[eni.VSwitch.VSwitchID]; ok && subnet.CIDR != nil {
					eni.VSwitch.CIDRBlock = subnet.CIDR.String()
					eni.ZoneID = subnet.AvailabilityZone
				}
			}

			if vpcs != nil {
				if vpc, ok := vpcs[eni.VPC.VPCID]; ok {
					eni.VPC.CIDRBlock = vpc.PrimaryCIDR
				}
			}

			eniRevision := ipamTypes.InterfaceRevision{Resource: eni.DeepCopy()}
			instances.Update(instanceID, eniRevision)
		}
	}

	return instances, nil
}

func (a *API) GetVSwitches(ctx context.Context) (ipamTypes.SubnetMap, error) {
	subnets := ipamTypes.SubnetMap{}

	a.mutex.RLock()
	defer a.mutex.RUnlock()

	for _, s := range a.subnets {
		subnets[s.ID] = s.DeepCopy()
	}
	return subnets, nil
}

func (a *API) GetVPC(ctx context.Context, vpcID string) (*ipamTypes.VirtualNetwork, error) {
	a.mutex.RLock()
	defer a.mutex.RUnlock()
	vpc, ok := a.vpcs[vpcID]
	if !ok {
		return nil, fmt.Errorf("can't found vpc by id %s", vpcID)
	}
	return vpc.DeepCopy(), nil
}

func (a *API) GetVPCs(ctx context.Context) (ipamTypes.VirtualNetworkMap, error) {
	vpcs := ipamTypes.VirtualNetworkMap{}

	a.mutex.RLock()
	defer a.mutex.RUnlock()

	for _, v := range a.vpcs {
		vpcs[v.ID] = v.DeepCopy()
	}
	return vpcs, nil
}

func (a *API) GetSecurityGroups(ctx context.Context) (types.SecurityGroupMap, error) {
	securityGroups := types.SecurityGroupMap{}

	a.mutex.RLock()
	defer a.mutex.RUnlock()

	for _, sg := range a.securityGroups {
		securityGroups[sg.ID] = sg.DeepCopy()
	}
	return securityGroups, nil
}

func (a *API) CreateNetworkInterface(ctx context.Context, secondaryPrivateIPCount int, vSwitchID string, groups []string, tags map[string]string) (string, *eniTypes.ENI, error) {
	a.mutex.Lock()
	defer a.mutex.Unlock()

	vsw, ok := a.subnets[vSwitchID]
	if !ok {
		return "", nil, fmt.Errorf("can not found vSwitch by id %s", vSwitchID)
	}
	if secondaryPrivateIPCount+1 > vsw.AvailableAddresses {
		return "", nil, fmt.Errorf("vSwitch %s has not enough addresses available", vsw.ID)
	}

	eniID := uuid.New().String()
	eni := &eniTypes.ENI{
		NetworkInterfaceID: eniID,
		VSwitch: eniTypes.VSwitch{
			VSwitchID: vSwitchID,
			CIDRBlock: vsw.CIDR.String(),
		},
		Type:             eniTypes.ENITypeSecondary,
		SecurityGroupIDs: groups,
		Tags:             tags,
	}
	for i := 0; i < secondaryPrivateIPCount+1; i++ {
		ip, err := a.allocator.AllocateNext()
		if err != nil {
			panic("Unable to allocate IP from allocator")
		}
		primary := false
		if eni.PrimaryIPAddress == "" {
			eni.PrimaryIPAddress = ip.String()
			primary = true
		}
		eni.PrivateIPSets = append(eni.PrivateIPSets, eniTypes.PrivateIPSet{
			PrivateIpAddress: ip.String(),
			Primary:          primary,
		})
	}

	vsw.AvailableAddresses -= secondaryPrivateIPCount + 1

	a.unattached[eniID] = eni
	return eniID, eni.DeepCopy(), nil
}

func (a *API) AttachNetworkInterface(ctx context.Context, instanceID, eniID string) error {
	a.mutex.Lock()
	defer a.mutex.Unlock()

	eni, ok := a.unattached[eniID]
	if !ok {
		return fmt.Errorf("ENI ID %s does not exist", eniID)
	}

	delete(a.unattached, eniID)

	if _, ok := a.enis[instanceID]; !ok {
		a.enis[instanceID] = ENIMap{}
	}

	a.enis[instanceID][eniID] = eni
	return nil
}

func (a *API) WaitENIAttached(ctx context.Context, eniID string) (string, error) {
	return "", nil
}

func (a *API) DeleteNetworkInterface(ctx context.Context, eniID string) error {
	a.mutex.Lock()
	defer a.mutex.Unlock()

	delete(a.unattached, eniID)
	for _, enis := range a.enis {
		if _, ok := enis[eniID]; ok {
			delete(enis, eniID)
			return nil
		}
	}
	return fmt.Errorf("ENI ID %s not found", eniID)
}

func (a *API) AssignPrivateIPAddresses(ctx context.Context, eniID string, toAllocate int) ([]string, error) {
	a.mutex.Lock()
	defer a.mutex.Unlock()

	for _, enis := range a.enis {
		if eni, ok := enis[eniID]; ok {
			subnet, ok := a.subnets[eni.VSwitch.VSwitchID]
			if !ok {
				return nil, fmt.Errorf("vSwitch %s not found", eni.VSwitch.VSwitchID)
			}

			if toAllocate > subnet.AvailableAddresses {
				return nil, fmt.Errorf("vSwitch %s don't have enough addresses available", eni.VSwitch.VSwitchID)
			}

			for i := 0; i < toAllocate; i++ {
				ip, err := a.allocator.AllocateNext()
				if err != nil {
					panic("Unable to allocate IP from allocator")
				}
				primary := false
				if eni.PrimaryIPAddress == "" {
					eni.PrimaryIPAddress = ip.String()
					primary = true
				}
				eni.PrivateIPSets = append(eni.PrivateIPSets, eniTypes.PrivateIPSet{
					PrivateIpAddress: ip.String(),
					Primary:          primary,
				})
			}
			subnet.AvailableAddresses -= toAllocate
			return nil, nil
		}
	}
	return nil, fmt.Errorf("unable to find ENI with ID %s", eniID)
}

func (a *API) UnassignPrivateIPAddresses(ctx context.Context, eniID string, addresses []string) error {
	a.mutex.Lock()
	defer a.mutex.Unlock()

	releaseMap := make(map[string]int)
	for _, addr := range addresses {
		// Validate given addresses
		ipaddr := net.ParseIP(addr)
		if ipaddr == nil {
			return fmt.Errorf("invalid IP address %s", addr)
		}
		releaseMap[addr] = 0
	}

	for _, enis := range a.enis {
		eni, ok := enis[eniID]
		if !ok {
			continue
		}
		subnet, ok := a.subnets[eni.VSwitch.VSwitchID]
		if !ok {
			return fmt.Errorf("vSwitch %s not found", eni.VSwitch.VSwitchID)
		}

		addressesAfterRelease := []eniTypes.PrivateIPSet{}

		for _, address := range eni.PrivateIPSets {
			if address.Primary {
				continue
			}
			_, ok := releaseMap[address.PrivateIpAddress]
			if !ok {
				addressesAfterRelease = append(addressesAfterRelease, address)
			} else {
				ip := net.ParseIP(address.PrivateIpAddress)
				a.allocator.Release(ip)
				subnet.AvailableAddresses++
			}
		}
		eni.PrivateIPSets = addressesAfterRelease
		return nil
	}
	return fmt.Errorf("unable to find ENI with ID %s", eniID)
}
