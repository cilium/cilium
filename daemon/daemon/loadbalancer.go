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
	"github.com/cilium/cilium/common/bpf"
	"github.com/cilium/cilium/common/types"
)

// addSVC2BPFMap adds the given bpf service to the bpf maps. If addRevNAT is set, adds the
// RevNAT value (feCilium.L3n4Addr) to the lb's RevNAT map for the given feCilium.ID.
func (d *Daemon) addSVC2BPFMap(feCilium types.L3n4AddrID, feBPF lbmap.ServiceKey,
	besBPF []lbmap.ServiceValue, addRevNAT bool) error {

	err := lbmap.AddSVC2BPFMap(feBPF, besBPF, addRevNAT, int(feCilium.ID))
	if err != nil {
		if addRevNAT {
			delete(d.loadBalancer.RevNATMap, feCilium.ID)
		}
		return err
	}
	if addRevNAT {
		d.loadBalancer.RevNATMap[feCilium.ID] = *feCilium.L3n4Addr.DeepCopy()
	}
	return nil
}

// SVCAdd adds a service from the given feL3n4Addr (frontend) and beL3n4Addr (backends).
// If addRevNAT is set, the RevNAT entry is also created for this particular service.
// If any of the backend addresses set in bes have a different L3 address type than the
// one set in fe, it returns an error without modifying the bpf LB map. If any backend
// entry fails while updating the LB map, the frontend won't be inserted in the LB map
// therefore there won't be any traffic going to the given backends.
// All of the backends added will be DeepCopied to the internal load balancer map.
func (d *Daemon) SVCAdd(feL3n4Addr types.L3n4AddrID, beL3n4Addr []types.L3n4Addr, addRevNAT bool) error {
	// We will move the slice to the loadbalancer map which have a mutex. If we don't
	// copy the slice we might risk changing memory that should be locked.
	beL3n4AddrCpy := []types.L3n4Addr{}
	for _, v := range beL3n4Addr {
		beL3n4AddrCpy = append(beL3n4AddrCpy, v)
	}

	svc := types.LBSVC{
		FE:  feL3n4Addr,
		BES: beL3n4AddrCpy,
	}

	fe, besValues, err := lbmap.LBSVC2ServiceKeynValue(svc)
	if err != nil {
		return err
	}

	feL3n4Uniq, err := feL3n4Addr.L3n4Addr.SHA256Sum()
	if err != nil {
		return err
	}

	d.loadBalancer.BPFMapMU.Lock()
	defer d.loadBalancer.BPFMapMU.Unlock()

	err = d.addSVC2BPFMap(feL3n4Addr, fe, besValues, addRevNAT)
	if err != nil {
		return err
	}

	d.loadBalancer.SVCMap[feL3n4Uniq] = svc

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

// SVCDeleteAll deletes all IPv4 addresses, if IPv4 is enabled on daemon, and all IPv6
// services stored on the daemon and on the bpf maps.
func (d *Daemon) SVCDeleteAll() error {
	d.loadBalancer.BPFMapMU.Lock()
	defer d.loadBalancer.BPFMapMU.Unlock()

	if d.conf.IPv4Enabled {
		if err := lbmap.Service4Map.DeleteAll(); err != nil {
			return err
		}
	}
	if err := lbmap.Service6Map.DeleteAll(); err != nil {
		return err
	}
	// TODO should we delete even if err is != nil?

	d.loadBalancer.SVCMap = map[string]types.LBSVC{}
	return nil
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
	revNATK, revNATV := lbmap.L3n4Addr2RevNatKeynValue(id, revNAT)

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

// RevNATDeleteAll deletes all RevNAT4, if IPv4 is enabled on daemon, and all RevNAT6
// stored on the daemon and on the bpf maps.
func (d *Daemon) RevNATDeleteAll() error {
	d.loadBalancer.BPFMapMU.Lock()
	defer d.loadBalancer.BPFMapMU.Unlock()

	if d.conf.IPv4Enabled {
		if err := lbmap.RevNat4Map.DeleteAll(); err != nil {
			return err
		}
	}
	if err := lbmap.RevNat6Map.DeleteAll(); err != nil {
		return err
	}
	// TODO should we delete even if err is != nil?

	d.loadBalancer.RevNATMap = map[types.ServiceID]types.L3n4Addr{}
	return nil
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

// SyncLBMap syncs the bpf lbmap with the daemon's lb map. All bpf entries will overwrite
// the daemon's LB map. If the bpf lbmap entry have a different service ID than the
// KVStore's ID, that entry will be updated on the bpf map accordingly with the new ID
// retrieved from the KVStore.
func (d *Daemon) SyncLBMap() error {
	d.loadBalancer.BPFMapMU.Lock()
	defer d.loadBalancer.BPFMapMU.Unlock()

	newSVCMap := types.SVCMap{}
	newRevNATMap := types.RevNATMap{}
	failedSyncSVC := []types.LBSVC{}
	failedSyncRevNAT := map[types.ServiceID]types.L3n4Addr{}

	parseSVCEntries := func(key bpf.MapKey, value bpf.MapValue) {
		svcKey := key.(lbmap.ServiceKey)
		//It's the frontend service so we don't add this one
		if svcKey.GetBackend() == 0 {
			return
		}
		svcValue := value.(lbmap.ServiceValue)
		fe, be, err := lbmap.ServiceKeynValue2FEnBE(svcKey, svcValue)
		if err != nil {
			log.Errorf("%s", err)
			return
		}
		if err := newSVCMap.AddFEnBE(fe, be, svcKey.GetBackend()); err != nil {
			log.Errorf("%s", err)
			return
		}
	}

	parseRevNATEntries := func(key bpf.MapKey, value bpf.MapValue) {
		revNatK := key.(lbmap.RevNatKey)
		revNatV := value.(lbmap.RevNatValue)
		fe, err := lbmap.RevNatValue2L3n4AddrID(revNatK, revNatV)
		if err != nil {
			log.Errorf("%s", err)
			return
		}
		newRevNATMap[fe.ID] = fe.L3n4Addr
	}

	addSVC2BPFMap := func(oldID types.ServiceID, svc types.LBSVC) error {
		// check if the reverser nat is present on the bpf map and update the
		// reverse nat key and delete the old one.
		revNAT, ok := newRevNATMap[oldID]
		if ok {
			revNATK, revNATV := lbmap.L3n4Addr2RevNatKeynValue(svc.FE.ID, revNAT)
			err := lbmap.UpdateRevNat(revNATK, revNATV)
			if err != nil {
				return fmt.Errorf("Unable to add revNAT: %s: %s."+
					" This entry will be removed from the bpf's LB map.", revNAT.String(), err)
			}

			// Remove the old entry from the bpf map.
			revNATK, _ = lbmap.L3n4Addr2RevNatKeynValue(oldID, revNAT)
			if err := lbmap.DeleteRevNat(revNATK); err != nil {
				log.Warningf("Unable to remove old rev NAT entry with ID %d: %s", oldID, err)
			}

			delete(newRevNATMap, oldID)
			newRevNATMap[svc.FE.ID] = revNAT
		}

		fe, besValues, err := lbmap.LBSVC2ServiceKeynValue(svc)
		if err != nil {
			return fmt.Errorf("Unable to create a BPF key and values for service FE: %s and backends: %+v. Error: %s."+
				" This entry will be removed from the bpf's LB map.", svc.FE.String(), svc.BES, err)
		}

		err = d.addSVC2BPFMap(svc.FE, fe, besValues, false)
		if err != nil {
			return fmt.Errorf("Unable to add service FE: %s: %s."+
				" This entry will be removed from the bpf's LB map.", svc.FE.String(), err)
		}
		return nil
	}

	if d.conf.IPv4Enabled {
		lbmap.Service4Map.Dump(lbmap.Service4DumpParser, parseSVCEntries)
		lbmap.RevNat4Map.Dump(lbmap.RevNat4DumpParser, parseRevNATEntries)
	}

	lbmap.Service6Map.Dump(lbmap.Service6DumpParser, parseSVCEntries)
	lbmap.RevNat6Map.Dump(lbmap.RevNat6DumpParser, parseRevNATEntries)

	// Let's check if the services read from the lbmap have the same ID set in the
	// KVStore.
	for k, svc := range newSVCMap {
		kvL3n4AddrID, err := d.PutL3n4Addr(svc.FE.L3n4Addr)
		if err != nil {
			log.Errorf("Unable to retrieve service ID of: %s from KVStore: %s."+
				" This entry will be removed from the bpf's LB map.", svc.FE.L3n4Addr.String(), err)
			failedSyncSVC = append(failedSyncSVC, svc)
			delete(newSVCMap, k)
			continue
		}

		if svc.FE.ID != kvL3n4AddrID.ID {
			log.Infof("Service ID was out of sync, got new ID %d -> %d", svc.FE.ID, kvL3n4AddrID.ID)
			oldID := svc.FE.ID
			svc.FE.ID = kvL3n4AddrID.ID
			if err := addSVC2BPFMap(oldID, svc); err != nil {
				log.Errorf("%s", err)

				failedSyncSVC = append(failedSyncSVC, svc)
				delete(newSVCMap, k)

				revNAT, ok := newRevNATMap[svc.FE.ID]
				if ok {
					// Revert the old revNAT
					newRevNATMap[oldID] = revNAT
					failedSyncRevNAT[svc.FE.ID] = revNAT
					delete(newRevNATMap, svc.FE.ID)
				}
				continue
			}
			newSVCMap[k] = svc
		}
	}

	// Clean services and rev nats that failed while restoring
	for _, svc := range failedSyncSVC {
		log.Debugf("Removing service: %s", svc.FE)
		feL3n4 := svc.FE
		var svcKey lbmap.ServiceKey
		if !feL3n4.IsIPv6() {
			svcKey = lbmap.NewService4Key(feL3n4.IP, feL3n4.Port, 0)
		} else {
			svcKey = lbmap.NewService6Key(feL3n4.IP, feL3n4.Port, 0)
		}

		svcKey.SetBackend(0)

		if err := lbmap.DeleteService(svcKey); err != nil {
			log.Warningf("Unable to clean service %s from BPF map: %s", svc.FE, err)
		}
	}

	for id, revNAT := range failedSyncRevNAT {
		log.Debugf("Removing revNAT: %s", revNAT)
		var revNATK lbmap.RevNatKey
		if !revNAT.IsIPv6() {
			revNATK = lbmap.NewRevNat4Key(uint16(id))
		} else {
			revNATK = lbmap.NewRevNat6Key(uint16(id))
		}

		if err := lbmap.DeleteRevNat(revNATK); err != nil {
			log.Warningf("Unable to clean rev NAT %s from BPF map: %s", revNAT, err)
		}
	}

	d.loadBalancer.SVCMap = newSVCMap
	d.loadBalancer.RevNATMap = newRevNATMap

	return nil
}
