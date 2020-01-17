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
	"strconv"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/u8proto"

	"github.com/sirupsen/logrus"
)

var log = logging.DefaultLogger.WithField(logfields.LogSubsys, "map-lb")

const (
	// Maximum number of entries in each hashtable
	MaxEntries = 65536
)

// LBBPFMap is an implementation of the LBMap interface.
type LBBPFMap struct{}

// UpsertService inserts or updates the given service in a BPF map.
//
// The corresponding backend entries (identified with the given backendIDs)
// have to exist before calling the function.
//
// The given prevBackendCount denotes a previous service backend entries count,
// so that the function can remove obsolete ones.
func (*LBBPFMap) UpsertService(
	svcID uint16, svcIP net.IP, svcPort uint16,
	backendIDs []uint16, prevBackendCount int,
	ipv6 bool, svcType loadbalancer.SVCType) error {

	var svcKey ServiceKey

	if svcID == 0 {
		return fmt.Errorf("Invalid svc ID 0")
	}

	if ipv6 {
		svcKey = NewService6Key(svcIP, svcPort, u8proto.ANY, 0)
	} else {
		svcKey = NewService4Key(svcIP, svcPort, u8proto.ANY, 0)
	}

	slot := 1
	svcVal := svcKey.NewValue().(ServiceValue)
	for _, backendID := range backendIDs {
		if backendID == 0 {
			return fmt.Errorf("Invalid backend ID 0")
		}
		svcVal.SetBackendID(loadbalancer.BackendID(backendID))
		svcVal.SetRevNat(int(svcID))
		svcKey.SetSlave(slot) // TODO(brb) Rename to SetSlot
		if err := updateServiceEndpoint(svcKey, svcVal); err != nil {
			return fmt.Errorf("Unable to update service entry %+v => %+v: %s",
				svcKey, svcVal, err)
		}
		slot++
	}

	zeroValue := svcKey.NewValue().(ServiceValue)
	zeroValue.SetRevNat(int(svcID)) // TODO change to uint16
	revNATKey := zeroValue.RevNatKey()
	revNATValue := svcKey.RevNatValue()
	if err := updateRevNatLocked(revNATKey, revNATValue); err != nil {
		return fmt.Errorf("Unable to update reverse NAT %+v => %+v: %s", revNATKey, revNATValue, err)
	}

	if err := updateMasterService(svcKey, len(backendIDs), int(svcID), svcType); err != nil {
		deleteRevNatLocked(revNATKey)
		return fmt.Errorf("Unable to update service %+v: %s", svcKey, err)
	}

	for i := slot; i <= prevBackendCount; i++ {
		svcKey.SetSlave(i)
		if err := deleteServiceLocked(svcKey); err != nil {
			log.WithFields(logrus.Fields{
				logfields.ServiceKey: svcKey,
				logfields.SlaveSlot:  svcKey.GetSlave(),
			}).WithError(err).Warn("Unable to delete service entry from BPF map")
		}
	}

	return nil
}

// DeleteService removes given service from a BPF map.
func (*LBBPFMap) DeleteService(svc loadbalancer.L3n4AddrID, backendCount int) error {
	var (
		svcKey    ServiceKey
		revNATKey RevNatKey
	)

	if svc.ID == 0 {
		return fmt.Errorf("Invalid svc ID 0")
	}

	if svc.IsIPv6() {
		svcKey = NewService6Key(svc.IP, svc.Port, u8proto.ANY, 0)
		revNATKey = NewRevNat6Key(uint16(svc.ID))
	} else {
		svcKey = NewService4Key(svc.IP, svc.Port, u8proto.ANY, 0)
		revNATKey = NewRevNat4Key(uint16(svc.ID))
	}

	for slot := 0; slot <= backendCount; slot++ {
		svcKey.SetSlave(slot)
		if err := svcKey.MapDelete(); err != nil {
			return fmt.Errorf("Unable to delete service entry %+v: %s", svcKey, err)
		}
	}

	if err := deleteRevNatLocked(revNATKey); err != nil {
		return fmt.Errorf("Unable to delete revNAT entry %+v: %s", revNATKey, err)
	}

	return nil
}

// AddBackend adds a backend into a BPF map.
func (*LBBPFMap) AddBackend(id uint16, ip net.IP, port uint16, ipv6 bool) error {
	var (
		backend Backend
		err     error
	)

	if id == 0 {
		return fmt.Errorf("Invalid backend ID 0")
	}

	if ipv6 {
		backend, err = NewBackend6(loadbalancer.BackendID(id), ip, port, u8proto.ANY)
	} else {
		backend, err = NewBackend4(loadbalancer.BackendID(id), ip, port, u8proto.ANY)
	}
	if err != nil {
		return fmt.Errorf("Unable to create backend (%d, %s, %d, %t): %s",
			id, ip, port, ipv6, err)
	}

	if err := updateBackend(backend); err != nil {
		return fmt.Errorf("Unable to add backend %+v: %s", backend, err)
	}

	return nil
}

// DeleteBackendByID removes a backend identified with the given ID from a BPF map.
func (*LBBPFMap) DeleteBackendByID(id uint16, ipv6 bool) error {
	var key BackendKey

	if id == 0 {
		return fmt.Errorf("Invalid backend ID 0")
	}

	if ipv6 {
		key = NewBackend6Key(loadbalancer.BackendID(id))
	} else {
		key = NewBackend4Key(loadbalancer.BackendID(id))
	}

	if err := deleteBackendLocked(key); err != nil {
		return fmt.Errorf("Unable to delete backend %d (%t): %s", id, ipv6, err)
	}

	return nil
}

func updateRevNatLocked(key RevNatKey, value RevNatValue) error {
	if key.GetKey() == 0 {
		return fmt.Errorf("invalid RevNat ID (0)")
	}
	if _, err := key.Map().OpenOrCreate(); err != nil {
		return err
	}

	return key.Map().Update(key.ToNetwork(), value.ToNetwork())
}

func deleteRevNatLocked(key RevNatKey) error {
	return key.Map().Delete(key.ToNetwork())
}

// DumpServiceMaps dumps the services from the BPF maps.
func (*LBBPFMap) DumpServiceMaps() ([]*loadbalancer.SVC, []error) {
	newSVCMap := svcMap{}
	errors := []error{}
	flagsCache := map[string]loadbalancer.ServiceFlags{}
	backendValueMap := map[loadbalancer.BackendID]BackendValue{}

	parseBackendEntries := func(key bpf.MapKey, value bpf.MapValue) {
		backendKey := key.(BackendKey)
		backendValue := value.DeepCopyMapValue().(BackendValue)
		backendValueMap[backendKey.GetID()] = backendValue
	}

	parseSVCEntries := func(key bpf.MapKey, value bpf.MapValue) {
		svcKey := key.DeepCopyMapKey().(ServiceKey)
		svcValue := value.DeepCopyMapValue().(ServiceValue)

		fe := svcFrontend(svcKey, svcValue)

		// Create master entry in case there are no backends.
		if svcKey.GetSlave() == 0 {
			// Build a cache of flags stored in the value of the master key to
			// map it later.
			// FIXME proto is being ignored everywhere in the datapath.
			addrStr := svcKey.GetAddress().String()
			portStr := strconv.Itoa(int(svcKey.GetPort()))
			flagsCache[net.JoinHostPort(addrStr, portStr)] = loadbalancer.ServiceFlags(svcValue.GetFlags())

			newSVCMap.addFE(fe)
			return
		}

		backendID := svcValue.GetBackendID()
		backendValue, found := backendValueMap[backendID]
		if !found {
			errors = append(errors, fmt.Errorf("backend %d not found", backendID))
			return
		}

		be := svcBackend(backendID, backendValue)
		newSVCMap.addFEnBE(fe, be, svcKey.GetSlave())
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

	newSVCList := make([]*loadbalancer.SVC, 0, len(newSVCMap))
	for hash := range newSVCMap {
		svc := newSVCMap[hash]
		addrStr := svc.Frontend.IP.String()
		portStr := strconv.Itoa(int(svc.Frontend.Port))
		host := net.JoinHostPort(addrStr, portStr)
		svc.Type = flagsCache[host].SVCType()
		newSVCList = append(newSVCList, &svc)
	}

	return newSVCList, errors
}

// DumpBackendMaps dumps the backend entries from the BPF maps.
func (*LBBPFMap) DumpBackendMaps() ([]*loadbalancer.Backend, error) {
	backendValueMap := map[loadbalancer.BackendID]BackendValue{}
	lbBackends := []*loadbalancer.Backend{}

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
		lbBackend := loadbalancer.NewBackend(backendID, proto, ip, port)
		lbBackends = append(lbBackends, lbBackend)
	}

	return lbBackends, nil
}

func updateMasterService(fe ServiceKey, nbackends int, revNATID int, svcType loadbalancer.SVCType) error {
	fe.SetSlave(0)
	zeroValue := fe.NewValue().(ServiceValue)
	zeroValue.SetCount(nbackends)
	zeroValue.SetRevNat(revNATID)
	zeroValue.SetFlags(loadbalancer.CreateSvcFlag(svcType).UInt8())

	return updateServiceEndpoint(fe, zeroValue)
}

func deleteServiceLocked(key ServiceKey) error {
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

func updateServiceEndpoint(key ServiceKey, value ServiceValue) error {
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

type svcMap map[string]loadbalancer.SVC

// addFE adds the give 'fe' to the svcMap without any backends. If it does not
// yet exist, an entry is created. Otherwise, the existing entry is left
// unchanged.
func (svcs svcMap) addFE(fe *loadbalancer.L3n4AddrID) *loadbalancer.SVC {
	hash := fe.Hash()
	lbsvc, ok := svcs[hash]
	if !ok {
		lbsvc = loadbalancer.SVC{Frontend: *fe}
		svcs[hash] = lbsvc
	}
	return &lbsvc
}

// addFEnBE adds the given 'fe' and 'be' to the svcMap. If 'fe' exists and beIndex is 0,
// the new 'be' will be appended to the list of existing backends. If beIndex is bigger
// than the size of existing backends slice, it will be created a new array with size of
// beIndex and the new 'be' will be inserted on index beIndex-1 of that new array. All
// remaining be elements will be kept on the same index and, in case the new array is
// larger than the number of backends, some elements will be empty.
func (svcs svcMap) addFEnBE(fe *loadbalancer.L3n4AddrID, be *loadbalancer.Backend, beIndex int) *loadbalancer.SVC {
	hash := fe.Hash()
	lbsvc, ok := svcs[hash]
	if !ok {
		var bes []loadbalancer.Backend
		if beIndex == 0 {
			bes = make([]loadbalancer.Backend, 1)
			bes[0] = *be
		} else {
			bes = make([]loadbalancer.Backend, beIndex)
			bes[beIndex-1] = *be
		}
		lbsvc = loadbalancer.SVC{
			Frontend: *fe,
			Backends: bes,
		}
	} else {
		var bes []loadbalancer.Backend
		if len(lbsvc.Backends) < beIndex {
			bes = make([]loadbalancer.Backend, beIndex)
			copy(bes, lbsvc.Backends)
			lbsvc.Backends = bes
		}
		if beIndex == 0 {
			lbsvc.Backends = append(lbsvc.Backends, *be)
		} else {
			lbsvc.Backends[beIndex-1] = *be
		}
	}

	svcs[hash] = lbsvc
	return &lbsvc
}
