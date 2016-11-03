//
// Copyright 2016 Authors of Cilium
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
//
package daemon

import (
	"fmt"

	"github.com/cilium/cilium/bpf/lbmap"
	"github.com/cilium/cilium/common/types"
)

// SVCAdd adds a service from the given feL3n4Addr (frontend) and beL3n4Addr (backends).
// If addRevNAT is set, the RevNAT entry is also created for this particular service.
// If any of the backend addresses set in bes have a different L3 address type than the
// one set in fe, it returns an error without modifying the bpf LB map. If any backend
// entry fails while updating the LB map, the frontend won't be inserted in the LB map
// therefore there won't be any traffic going to the given backends.
// All of the backends added will be DeepCopied to the internal load balancer map.
func (d *Daemon) SVCAdd(feL3n4Addr types.L3n4AddrID, beL3n4Addr []types.L3n4Addr, addRevNAT bool) error {
	if feL3n4Addr.ID == 0 {
		return fmt.Errorf("invalid ID (%d)", feL3n4Addr.ID)
	}

	// We will move the slice to the loadbalancer map which have a mutex. If we don't
	// copy the slice we might risk changing memory that should be locked.
	beL3n4AddrCpy := []types.L3n4Addr{}
	for _, v := range beL3n4Addr {
		beL3n4AddrCpy = append(beL3n4AddrCpy, v)
	}

	var fe lbmap.ServiceKey
	if !feL3n4Addr.IsIPv6() {
		fe = lbmap.NewService4Key(feL3n4Addr.IP, feL3n4Addr.Port, 0)
	} else {
		fe = lbmap.NewService6Key(feL3n4Addr.IP, feL3n4Addr.Port, 0)
	}

	// Create a list of ServiceValues so we know everything is safe to put in the lb
	// map
	besValues := []lbmap.ServiceValue{}
	for _, be := range beL3n4AddrCpy {
		beValue := fe.NewValue().(lbmap.ServiceValue)
		if err := beValue.SetAddress(be.IP); err != nil {
			return err
		}
		beValue.SetPort(uint16(be.Port))
		beValue.SetRevNat(int(feL3n4Addr.ID))

		besValues = append(besValues, beValue)
	}

	feL3n4Uniq, err := feL3n4Addr.L3n4Addr.SHA256Sum()
	if err != nil {
		return err
	}

	d.loadBalancer.BPFMapMU.Lock()
	defer d.loadBalancer.BPFMapMU.Unlock()

	// Put all the backend services first
	nSvcs := 1
	for _, be := range besValues {
		fe.SetBackend(nSvcs)
		if err := lbmap.UpdateService(fe, be); err != nil {
			return fmt.Errorf("unable to update service %+v with the value %+v: %s", fe, be, err)
		}
		nSvcs++
	}

	if addRevNAT {
		zeroValue := fe.NewValue().(lbmap.ServiceValue)
		zeroValue.SetRevNat(int(feL3n4Addr.ID))
		revNATKey := zeroValue.RevNatKey()
		revNATValue := fe.RevNatValue()
		if err := lbmap.UpdateRevNat(revNATKey, revNATValue); err != nil {
			return fmt.Errorf("unable to update reverse NAT %+v with value %+v, %s", revNATKey, revNATValue, err)
		}
		defer func() {
			if err != nil {
				lbmap.DeleteRevNat(revNATKey)
				delete(d.loadBalancer.RevNATMap, feL3n4Addr.ID)
			}
		}()
		d.loadBalancer.RevNATMap[feL3n4Addr.ID] = *feL3n4Addr.L3n4Addr.DeepCopy()
	}

	fe.SetBackend(0)
	zeroValue := fe.NewValue().(lbmap.ServiceValue)
	zeroValue.SetCount(nSvcs - 1)

	err = lbmap.UpdateService(fe, zeroValue)
	if err != nil {
		return fmt.Errorf("unable to update service %+v with the value %+v: %s", fe, zeroValue, err)
	}

	d.loadBalancer.SVCMap[feL3n4Uniq] = types.LBSVC{
		FE:  feL3n4Addr,
		BES: beL3n4AddrCpy,
	}

	return nil
}

// SVCDelete deletes the frontend from the local bpf map.
func (d *Daemon) SVCDelete(feL3n4 types.L3n4Addr) error {
	feL3n4Uniq, err := feL3n4.SHA256Sum()
	if err != nil {
		return err
	}

	var svcKey lbmap.ServiceKey
	if !feL3n4.IsIPv6() {
		svcKey = lbmap.NewService4Key(feL3n4.IP, feL3n4.Port, 0)
	} else {
		svcKey = lbmap.NewService6Key(feL3n4.IP, feL3n4.Port, 0)
	}

	svcKey.SetBackend(0)

	d.loadBalancer.BPFMapMU.Lock()
	defer d.loadBalancer.BPFMapMU.Unlock()
	err = lbmap.DeleteService(svcKey)
	// TODO should we delete even if err is != nil?
	if err == nil {
		delete(d.loadBalancer.SVCMap, feL3n4Uniq)
	}
	return err
}

// SVCDeleteBySHA256Sum deletes the frontend from the local bpf map by its SHA256Sum.
func (d *Daemon) SVCDeleteBySHA256Sum(feL3n4SHA256Sum string) error {
	d.loadBalancer.BPFMapMU.Lock()
	defer d.loadBalancer.BPFMapMU.Unlock()

	svc, ok := d.loadBalancer.SVCMap[feL3n4SHA256Sum]
	if !ok {
		return nil
	}
	feL3n4 := svc.FE

	var svcKey lbmap.ServiceKey
	if !feL3n4.IsIPv6() {
		svcKey = lbmap.NewService4Key(feL3n4.IP, feL3n4.Port, 0)
	} else {
		svcKey = lbmap.NewService6Key(feL3n4.IP, feL3n4.Port, 0)
	}

	svcKey.SetBackend(0)

	err := lbmap.DeleteService(svcKey)
	// TODO should we delete even if err is != nil?
	if err == nil {
		delete(d.loadBalancer.SVCMap, feL3n4SHA256Sum)
	}
	return err
}

// SVCGet returns a DeepCopied frontend with its backends.
func (d *Daemon) SVCGet(feL3n4 types.L3n4Addr) (*types.LBSVC, error) {
	feL3n4Uniq, err := feL3n4.SHA256Sum()
	if err != nil {
		return nil, err
	}
	return d.SVCGetBySHA256Sum(feL3n4Uniq)
}

// SVCGetBySHA256Sum returns a DeepCopied frontend with its backends.
func (d *Daemon) SVCGetBySHA256Sum(feL3n4SHA256Sum string) (*types.LBSVC, error) {
	d.loadBalancer.BPFMapMU.RLock()
	defer d.loadBalancer.BPFMapMU.RUnlock()

	if v, ok := d.loadBalancer.SVCMap[feL3n4SHA256Sum]; !ok {
		return nil, nil
	} else {
		// We will move the slice from the loadbalancer map which have a mutex. If
		// we don't copy the slice we might risk changing memory that should be
		// locked.
		beL3n4AddrCpy := []types.L3n4Addr{}
		for _, v := range v.BES {
			beL3n4AddrCpy = append(beL3n4AddrCpy, v)
		}
		return &types.LBSVC{
			FE:  *v.FE.DeepCopy(),
			BES: beL3n4AddrCpy,
		}, nil
	}
}

// SVCDump dumps a DeepCopy of the cilium's loadbalancer.
func (d *Daemon) SVCDump() ([]types.LBSVC, error) {
	dump := []types.LBSVC{}

	d.loadBalancer.BPFMapMU.RLock()
	defer d.loadBalancer.BPFMapMU.RUnlock()

	for _, v := range d.loadBalancer.SVCMap {
		beL3n4AddrCpy := []types.L3n4Addr{}
		for _, v := range v.BES {
			beL3n4AddrCpy = append(beL3n4AddrCpy, v)
		}
		dump = append(dump, types.LBSVC{FE: *v.FE.DeepCopy(), BES: beL3n4AddrCpy})
	}

	return dump, nil
}

// RevNATAdd deep copies the given revNAT address to the cilium lbmap with the given id.
func (d *Daemon) RevNATAdd(id types.ServiceID, revNAT types.L3n4Addr) error {
	if id == 0 {
		return fmt.Errorf("invalid ID (%d)", id)
	}
	var (
		revNATK lbmap.RevNatKey
		revNATV lbmap.RevNatValue
	)
	if !revNAT.IsIPv6() {
		revNATK = lbmap.NewRevNat4Key(uint16(id))
		revNATV = lbmap.NewRevNat4Value(revNAT.IP, revNAT.Port)
	} else {
		revNATK = lbmap.NewRevNat6Key(uint16(id))
		revNATV = lbmap.NewRevNat6Value(revNAT.IP, revNAT.Port)
	}

	d.loadBalancer.BPFMapMU.Lock()
	defer d.loadBalancer.BPFMapMU.Unlock()

	err := lbmap.UpdateRevNat(revNATK, revNATV)
	if err != nil {
		return err
	}

	d.loadBalancer.RevNATMap[id] = *revNAT.DeepCopy()
	return nil
}

// RevNATDelete deletes the revNatKey from the local bpf map.
func (d *Daemon) RevNATDelete(id types.ServiceID) error {
	d.loadBalancer.BPFMapMU.Lock()
	defer d.loadBalancer.BPFMapMU.Unlock()

	revNAT, ok := d.loadBalancer.RevNATMap[id]
	if !ok {
		return nil
	}

	var revNATK lbmap.RevNatKey
	if !revNAT.IsIPv6() {
		revNATK = lbmap.NewRevNat4Key(uint16(id))
	} else {
		revNATK = lbmap.NewRevNat6Key(uint16(id))
	}

	err := lbmap.DeleteRevNat(revNATK)
	// TODO should we delete even if err is != nil?
	if err == nil {
		delete(d.loadBalancer.RevNATMap, id)
	}
	return err
}

// RevNATGet returns a DeepCopy of the revNAT found with the given ID or nil if not found.
func (d *Daemon) RevNATGet(id types.ServiceID) (*types.L3n4Addr, error) {
	d.loadBalancer.BPFMapMU.RLock()
	defer d.loadBalancer.BPFMapMU.RUnlock()

	revNAT, ok := d.loadBalancer.RevNATMap[id]
	if !ok {
		return nil, nil
	}
	return revNAT.DeepCopy(), nil
}

// RevNATDump dumps a DeepCopy of the cilium's loadbalancer.
func (d *Daemon) RevNATDump() ([]types.L3n4AddrID, error) {
	dump := []types.L3n4AddrID{}

	d.loadBalancer.BPFMapMU.RLock()
	defer d.loadBalancer.BPFMapMU.RUnlock()

	for k, v := range d.loadBalancer.RevNATMap {
		dump = append(dump, types.L3n4AddrID{
			ID:       k,
			L3n4Addr: *v.DeepCopy(),
		})
	}

	return dump, nil
}
