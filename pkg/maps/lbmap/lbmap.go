// Copyright 2016-2019 Authors of Cilium
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

package lbmap

import (
	"fmt"
	"net"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/u8proto"

	"github.com/sirupsen/logrus"
)

var (
	log = logging.DefaultLogger.WithField(logfields.LogSubsys, "map-lb")

	// mutex protects access to the BPF map to guarantee atomicity if a
	// transaction must be split across multiple map access operations.
	mutex lock.RWMutex
)

const (
	// Maximum number of entries in each hashtable
	MaxEntries   = 65536
	maxFrontEnds = 256
	// MaxSeq is used by daemon for generating bpf define LB_RR_MAX_SEQ.
	MaxSeq = 31
)

var (
	// cache contains *all* services of both IPv4 and IPv6 based maps
	// combined
	cache = newLBMapCache()
)

func UpsertService(
	svcID uint16, svcIP net.IP, svcPort uint16,
	backendIDs []uint16, prevBackendCount int,
	ipv6 bool) error {

	var (
		svcKey ServiceKeyV2
		err    error
	)

	if ipv6 {
		svcKey = NewService6KeyV2(svcIP, svcPort, u8proto.ANY, 0)
	} else {
		svcKey = NewService4KeyV2(svcIP, svcPort, u8proto.ANY, 0)
	}

	slot := 1
	svcVal := svcKey.NewValue().(ServiceValueV2)
	for _, backendID := range backendIDs {
		svcVal.SetBackendID(loadbalancer.BackendID(backendID))
		svcVal.SetRevNat(int(svcID))
		svcKey.SetSlave(slot) // TODO rename
		if err := updateServiceEndpointV2(svcKey, svcVal); err != nil {
			return fmt.Errorf("Unable to update service entry %+v => %+v: %s",
				svcKey, svcVal, err)
		}
		slot++
	}

	zeroValue := svcKey.NewValue().(ServiceValueV2)
	zeroValue.SetRevNat(int(svcID)) // TODO change to uint16
	revNATKey := zeroValue.RevNatKey()
	revNATValue := svcKey.RevNatValue()
	if err := updateRevNatLocked(revNATKey, revNATValue); err != nil {
		return fmt.Errorf("Unable to update reverse NAT %+v => %+v: %s", revNATKey, revNATValue, err)
	}
	defer func() {
		if err != nil {
			deleteRevNatLocked(revNATKey)
		}
	}()

	if err = updateMasterServiceV2(svcKey, len(backendIDs), int(svcID)); err != nil {
		return fmt.Errorf("Unable to update service %+v: %s", svcKey, err)
	}

	for i := slot; i <= prevBackendCount; i++ {
		svcKey.SetSlave(i)
		if err := deleteServiceLockedV2(svcKey); err != nil {
			// TODO(brb) maybe just log as it is not so critical
			return fmt.Errorf("Unable to delete service %+v: %s", svcKey, err)
		}
	}

	return nil
}

func DeleteService(svc loadbalancer.L3n4AddrID, backends []loadbalancer.LBBackEnd) error {
	var (
		svcKey    ServiceKeyV2
		revNATKey RevNatKey
	)

	if svc.IsIPv6() {
		svcKey = NewService6KeyV2(svc.IP, svc.Port, u8proto.ANY, 0)
		revNATKey = NewRevNat6Key(uint16(svc.ID))
	} else {
		svcKey = NewService4KeyV2(svc.IP, svc.Port, u8proto.ANY, 0)
		revNATKey = NewRevNat4Key(uint16(svc.ID))
	}

	for slot := 0; slot <= len(backends); slot++ {
		svcKey.SetSlave(slot)
		if err := svcKey.MapDelete(); err != nil {
			return err
		}
	}

	if err := deleteRevNatLocked(revNATKey); err != nil {
		return fmt.Errorf("Unable to delete revNAT entry %d: %s", svc.ID, err)
	}

	return nil
}

func AddBackend(id uint16, ip net.IP, port uint16, ipv6 bool) error {
	var (
		backend Backend
		err     error
	)

	if ipv6 {
		backend, err = NewBackend6(loadbalancer.BackendID(id), ip, port, u8proto.ANY)
	} else {
		backend, err = NewBackend4(loadbalancer.BackendID(id), ip, port, u8proto.ANY)
	}

	if err != nil {
		return fmt.Errorf("Unable to create backend (%d, %s, %d, %t): %s",
			id, ip, port, ipv6)
	}

	if err := updateBackend(backend); err != nil {
		return fmt.Errorf("Unable to add backend %q: %s", backend, err)
	}

	return nil
}

func DeleteBackendByID(id uint16, ipv6 bool) error {
	var key BackendKey

	if ipv6 {
		key = NewBackend6Key(loadbalancer.BackendID(id))
	} else {
		key = NewBackend4Key(loadbalancer.BackendID(id))
	}

	if err := deleteBackendLocked(key); err != nil {
		return fmt.Errorf("Unable to remove backend %d (%t): %s", id, ipv6, err)
	}

	return nil
}

func updateRevNatLocked(key RevNatKey, value RevNatValue) error {
	log.WithFields(logrus.Fields{
		logfields.BPFMapKey:   key,
		logfields.BPFMapValue: value,
	}).Debug("adding revNat to lbmap")

	if key.GetKey() == 0 {
		return fmt.Errorf("invalid RevNat ID (0)")
	}
	if _, err := key.Map().OpenOrCreate(); err != nil {
		return err
	}

	return key.Map().Update(key.ToNetwork(), value.ToNetwork())
}

func deleteRevNatLocked(key RevNatKey) error {
	log.WithField(logfields.BPFMapKey, key).Debug("deleting RevNatKey")

	return key.Map().Delete(key.ToNetwork())
}

// DumpServiceMapsToUserspaceV2 dumps the services in the same way as
// DumpServiceMapsToUserspace.
func DumpServiceMapsToUserspaceV2() (loadbalancer.SVCMap, []*loadbalancer.LBSVC, []error) {
	mutex.RLock()
	defer mutex.RUnlock()

	newSVCMap := loadbalancer.SVCMap{}
	newSVCList := []*loadbalancer.LBSVC{}
	errors := []error{}
	idCache := map[string]loadbalancer.ServiceID{}
	backendValueMap := map[loadbalancer.BackendID]BackendValue{}

	parseBackendEntries := func(key bpf.MapKey, value bpf.MapValue) {
		backendKey := key.(BackendKey)
		backendValue := value.DeepCopyMapValue().(BackendValue)
		backendValueMap[backendKey.GetID()] = backendValue
	}

	parseSVCEntries := func(key bpf.MapKey, value bpf.MapValue) {
		svcKey := key.DeepCopyMapKey().(ServiceKeyV2)
		svcValue := value.DeepCopyMapValue().(ServiceValueV2)

		// Skip master service
		if svcKey.GetSlave() == 0 {
			return
		}

		backendID := svcValue.GetBackendID()

		scopedLog := log.WithFields(logrus.Fields{
			logfields.BPFMapKey:   svcKey,
			logfields.BPFMapValue: svcValue,
		})

		backendValue, found := backendValueMap[backendID]
		if !found {
			errors = append(errors, fmt.Errorf("backend %d not found", backendID))
			return
		}

		scopedLog.Debug("parsing service mapping v2")
		fe, be := serviceKeynValuenBackendValue2FEnBE(svcKey, svcValue, backendID, backendValue)

		// Build a cache to map frontend IP to service ID. The master
		// service key does not have the service ID set so the cache
		// needs to be built based on backend key entries.
		if k := svcValue.RevNatKey().GetKey(); k != uint16(0) {
			idCache[fe.String()] = loadbalancer.ServiceID(k)
		}

		svc := newSVCMap.AddFEnBE(fe, be, svcKey.GetSlave())
		newSVCList = append(newSVCList, svc)
	}

	if option.Config.EnableIPv4 {
		// TODO(brb) optimization: instead of dumping the backend map, we can
		// pass its content to the function.
		err := Backend4Map.DumpWithCallback(parseBackendEntries)
		if err != nil {
			errors = append(errors, err)
		}
		err = Service4MapV2.DumpWithCallback(parseSVCEntries)
		if err != nil {
			errors = append(errors, err)
		}
	}

	if option.Config.EnableIPv6 {
		// TODO(brb) same ^^ optimization applies here as well.
		err := Backend6Map.DumpWithCallback(parseBackendEntries)
		if err != nil {
			errors = append(errors, err)
		}
		err = Service6MapV2.DumpWithCallback(parseSVCEntries)
		if err != nil {
			errors = append(errors, err)
		}
	}

	// serviceKeynValue2FEnBE() cannot fill in the service ID reliably as
	// not all BPF map entries contain the service ID. Do a pass over all
	// parsed entries and fill in the service ID
	for i := range newSVCList {
		newSVCList[i].FE.ID = loadbalancer.ID(idCache[newSVCList[i].FE.String()])
	}

	// Do the same for the svcMap
	for key, svc := range newSVCMap {
		svc.FE.ID = loadbalancer.ID(idCache[svc.FE.String()])
		newSVCMap[key] = svc
	}

	return newSVCMap, newSVCList, errors
}

// DumpBackendMapsToUserspace dumps the backend entries from the BPF maps.
func DumpBackendMapsToUserspace() (map[BackendAddrID]*loadbalancer.LBBackEnd, error) {
	mutex.RLock()
	defer mutex.RUnlock()

	backendValueMap := map[loadbalancer.BackendID]BackendValue{}
	lbBackends := map[BackendAddrID]*loadbalancer.LBBackEnd{}

	parseBackendEntries := func(key bpf.MapKey, value bpf.MapValue) {
		// No need to deep copy the key because we are using the ID which
		// is a value.
		backendKey := key.(BackendKey)
		backendValue := value.DeepCopyMapValue().(BackendValue)
		backendValueMap[backendKey.GetID()] = backendValue
	}

	if option.Config.EnableIPv4 {
		err := Backend4Map.DumpWithCallback(parseBackendEntries)
		if err != nil {
			return nil, fmt.Errorf("Unable to dump lb4 backends map: %s", err)
		}
	}

	if option.Config.EnableIPv6 {
		err := Backend6Map.DumpWithCallback(parseBackendEntries)
		if err != nil {
			return nil, fmt.Errorf("Unable to dump lb6 backends map: %s", err)
		}
	}

	for backendID, backendVal := range backendValueMap {
		ip := backendVal.GetAddress()
		port := backendVal.GetPort()
		proto := loadbalancer.NONE
		lbBackend := loadbalancer.NewLBBackEnd(backendID, proto, ip, port)
		lbBackends[backendVal.BackendAddrID()] = lbBackend
	}

	return lbBackends, nil
}

func updateMasterServiceV2(fe ServiceKeyV2, nbackends int, revNATID int) error {
	fe.SetSlave(0)
	zeroValue := fe.NewValue().(ServiceValueV2)
	zeroValue.SetCount(nbackends)
	zeroValue.SetRevNat(revNATID)

	return updateServiceEndpointV2(fe, zeroValue)
}

func deleteServiceLockedV2(key ServiceKeyV2) error {
	return key.Map().Delete(key.ToNetwork())
}

func updateBackend(backend Backend) error {
	if _, err := backend.Map().OpenOrCreate(); err != nil {
		return err
	}
	return backend.Map().Update(backend.GetKey(), backend.GetValue().ToNetwork())
}

func deleteBackendLocked(key BackendKey) error {
	return key.Map().Delete(key)
}

func updateServiceEndpointV2(key ServiceKeyV2, value ServiceValueV2) error {
	log.WithFields(logrus.Fields{
		logfields.ServiceKey:   key,
		logfields.ServiceValue: value,
		logfields.SlaveSlot:    key.GetSlave(),
	}).Debug("Upserting service entry")

	if key.GetSlave() != 0 && value.RevNatKey().GetKey() == 0 {
		return fmt.Errorf("invalid RevNat ID (0) in the Service Value")
	}
	if _, err := key.Map().OpenOrCreate(); err != nil {
		return err
	}

	return key.Map().Update(key.ToNetwork(), value.ToNetwork())
}

// DeleteServiceV2 deletes a service from the lbmap and deletes backends of it if
// they are not used by any other service.
//
//The given key has to be of the master service.
func DeleteServiceV2(svc loadbalancer.L3n4AddrID, releaseBackendID func(loadbalancer.BackendID)) error {
	mutex.Lock()
	defer mutex.Unlock()

	var (
		svcKey    ServiceKeyV2
		revNATKey RevNatKey
	)

	isIPv6 := svc.IsIPv6()

	log.WithField(logfields.ServiceName, svc).Debug("Deleting service")

	if isIPv6 {
		svcKey = NewService6KeyV2(svc.IP, svc.Port, u8proto.ANY, 0)
		revNATKey = NewRevNat6Key(uint16(svc.ID))
	} else {
		svcKey = NewService4KeyV2(svc.IP, svc.Port, u8proto.ANY, 0)
		revNATKey = NewRevNat4Key(uint16(svc.ID))
	}

	backendsToRemove, backendsCount, err := cache.removeServiceV2(svcKey)
	if err != nil {
		return err
	}

	for slot := 0; slot <= backendsCount; slot++ {
		svcKey.SetSlave(slot)
		if err := svcKey.MapDelete(); err != nil {
			return err
		}
	}

	for _, backendKey := range backendsToRemove {
		if err := deleteBackendLocked(backendKey); err != nil {
			return fmt.Errorf("Unable to delete backend with ID %d: %s", backendKey, err)
		}
		releaseBackendID(backendKey.GetID())
		log.WithField(logfields.BackendID, backendKey).Debug("Deleted backend")
	}

	if err := deleteRevNatLocked(revNATKey); err != nil {
		return fmt.Errorf("Unable to delete revNAT entry %d: %s", svc.ID, err)
	}

	return nil
}
