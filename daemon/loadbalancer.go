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

package main

import (
	"fmt"
	"time"

	"github.com/cilium/cilium/api/v1/models"
	. "github.com/cilium/cilium/api/v1/server/restapi/service"
	"github.com/cilium/cilium/pkg/api"
	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/maps/lbmap"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/service"

	"github.com/go-openapi/runtime/middleware"
	"github.com/sirupsen/logrus"
)

// addSVC2BPFMap adds the given bpf service to the bpf maps. If addRevNAT is set, adds the
// RevNAT value (feCilium.L3n4Addr) to the lb's RevNAT map for the given feCilium.ID.
func (d *Daemon) addSVC2BPFMap(feCilium loadbalancer.L3n4AddrID, feBPF lbmap.ServiceKey,
	besBPF []lbmap.ServiceValue,
	svcKeyV2 lbmap.ServiceKeyV2, svcValuesV2 []lbmap.ServiceValueV2, backendsV2 []lbmap.Backend,
	addRevNAT bool) error {
	log.WithField(logfields.ServiceName, feCilium.String()).Debug("adding service to BPF maps")

	revNATID := int(feCilium.ID)

	if err := lbmap.UpdateService(feBPF, besBPF, addRevNAT, revNATID,
		option.Config.EnableLegacyServices,
		service.AcquireBackendID, service.DeleteBackendID); err != nil {
		if addRevNAT {
			delete(d.loadBalancer.RevNATMap, loadbalancer.ServiceID(feCilium.ID))
		}
		return err
	}

	if addRevNAT {
		log.WithField(logfields.ServiceName, feCilium.String()).Debug("adding service to RevNATMap")
		d.loadBalancer.RevNATMap[loadbalancer.ServiceID(feCilium.ID)] = *feCilium.L3n4Addr.DeepCopy()
	}
	return nil
}

// SVCAdd is the public method to add services. We assume the ID provided is not in
// sync with the KVStore. If that's the, case the service won't be used and an error is
// returned to the caller.
//
// Returns true if service was created.
func (d *Daemon) SVCAdd(feL3n4Addr loadbalancer.L3n4AddrID, be []loadbalancer.LBBackEnd, addRevNAT bool) (bool, error) {
	log.WithField(logfields.ServiceID, feL3n4Addr.String()).Debug("adding service")
	if feL3n4Addr.ID == 0 {
		return false, fmt.Errorf("invalid service ID 0")
	}
	// Check if the service is already registered with this ID.
	feAddr, err := service.GetID(uint32(feL3n4Addr.ID))
	if err != nil {
		return false, fmt.Errorf("unable to get service %d: %s", feL3n4Addr.ID, err)
	}
	if feAddr == nil {
		feAddr, err = service.AcquireID(feL3n4Addr.L3n4Addr, uint32(feL3n4Addr.ID))
		if err != nil {
			return false, fmt.Errorf("unable to store service %s in kvstore: %s", feL3n4Addr.String(), err)
		}
		// This won't be atomic so we need to check if the baseID, feL3n4Addr.ID was given to the service
		if feAddr.ID != feL3n4Addr.ID {
			return false, fmt.Errorf("the service provided %s is already registered with ID %d, please use that ID instead of %d", feL3n4Addr.L3n4Addr.String(), feAddr.ID, feL3n4Addr.ID)
		}
	}

	feAddr256Sum := feAddr.L3n4Addr.SHA256Sum()
	feL3n4Addr256Sum := feL3n4Addr.L3n4Addr.SHA256Sum()

	if feAddr256Sum != feL3n4Addr256Sum {
		return false, fmt.Errorf("service ID %d is already registered to L3n4Addr %s, please choose a different ID", feL3n4Addr.ID, feAddr.String())
	}

	return d.svcAdd(feL3n4Addr, be, addRevNAT)
}

// svcAdd adds a service from the given feL3n4Addr (frontend) and LBBackEnd (backends).
// If addRevNAT is set, the RevNAT entry is also created for this particular service.
// If any of the backend addresses set in bes have a different L3 address type than the
// one set in fe, it returns an error without modifying the bpf LB map. If any backend
// entry fails while updating the LB map, the frontend won't be inserted in the LB map
// therefore there won't be any traffic going to the given backends.
// All of the backends added will be DeepCopied to the internal load balancer map.
func (d *Daemon) svcAdd(feL3n4Addr loadbalancer.L3n4AddrID, bes []loadbalancer.LBBackEnd, addRevNAT bool) (bool, error) {
	scopedLog := log.WithFields(logrus.Fields{
		logfields.ServiceID: feL3n4Addr.String(),
		logfields.Object:    logfields.Repr(bes),
	})
	scopedLog.Debug("adding service")

	// Move the slice to the loadbalancer map which has a mutex. If we don't
	// copy the slice we might risk changing memory that should be locked.
	beCpy := []loadbalancer.LBBackEnd{}
	for _, v := range bes {
		beCpy = append(beCpy, v)
	}

	svc := loadbalancer.LBSVC{
		FE:     feL3n4Addr,
		BES:    beCpy,
		Sha256: feL3n4Addr.L3n4Addr.SHA256Sum(),
	}

	fe, besValues, err := lbmap.LBSVC2ServiceKeynValue(svc)
	if err != nil {
		return false, err
	}

	svcKeyV2, svcValuesV2, backendsV2, err := lbmap.LBSVC2ServiceKeynValuenBackendV2(&svc)
	if err != nil {
		return false, err
	}

	d.loadBalancer.BPFMapMU.Lock()
	defer d.loadBalancer.BPFMapMU.Unlock()

	err = d.addSVC2BPFMap(feL3n4Addr, fe, besValues, svcKeyV2, svcValuesV2, backendsV2, addRevNAT)
	if err != nil {
		return false, err
	}

	// Fill the just acquired backend IDs to ensure the consistent ordering
	// of the backends when listing services. This step will go away once
	// we start acquiring backend IDs in this module.
	for i, be := range svc.BES {
		id, err := service.LookupBackendID(be.L3n4Addr)
		if err != nil {
			scopedLog.WithField(logfields.BackendName, be.L3n4Addr).WithError(err).
				Warning("Unable to lookup backend ID")
			continue
		}
		svc.BES[i].ID = id
	}

	return d.loadBalancer.AddService(svc), nil
}

type putServiceID struct {
	d *Daemon
}

func NewPutServiceIDHandler(d *Daemon) PutServiceIDHandler {
	return &putServiceID{d: d}
}

func (h *putServiceID) Handle(params PutServiceIDParams) middleware.Responder {
	log.WithField(logfields.Params, logfields.Repr(params)).Debug("PUT /service/{id} request")

	f, err := loadbalancer.NewL3n4AddrFromModel(params.Config.FrontendAddress)
	if err != nil {
		return api.Error(PutServiceIDInvalidFrontendCode, err)
	}

	frontend := loadbalancer.L3n4AddrID{
		L3n4Addr: *f,
		ID:       loadbalancer.ID(params.Config.ID),
	}

	backends := []loadbalancer.LBBackEnd{}
	for _, v := range params.Config.BackendAddresses {
		b, err := loadbalancer.NewLBBackEndFromBackendModel(v)
		if err != nil {
			return api.Error(PutServiceIDInvalidBackendCode, err)
		}
		backends = append(backends, *b)
	}

	revnat := false
	if params.Config.Flags != nil {
		revnat = params.Config.Flags.DirectServerReturn
	}

	// FIXME
	// Add flag to indicate whether service should be registered in
	// global key value store

	if created, err := h.d.SVCAdd(frontend, backends, revnat); err != nil {
		return api.Error(PutServiceIDFailureCode, err)
	} else if created {
		return NewPutServiceIDCreated()
	} else {
		return NewPutServiceIDOK()
	}
}

type deleteServiceID struct {
	d *Daemon
}

func NewDeleteServiceIDHandler(d *Daemon) DeleteServiceIDHandler {
	return &deleteServiceID{d: d}
}

func (h *deleteServiceID) Handle(params DeleteServiceIDParams) middleware.Responder {
	log.WithField(logfields.Params, logfields.Repr(params)).Debug("DELETE /service/{id} request")

	d := h.d
	d.loadBalancer.BPFMapMU.Lock()
	defer d.loadBalancer.BPFMapMU.Unlock()

	svc, ok := d.loadBalancer.SVCMapID[loadbalancer.ServiceID(params.ID)]

	if !ok {
		return NewDeleteServiceIDNotFound()
	}

	// FIXME: How to handle error?
	err := service.DeleteID(uint32(params.ID))

	if err != nil {
		log.WithError(err).Warn("error, DeleteL3n4AddrIDByUUID failed")
	}

	if err := h.d.svcDelete(svc); err != nil {
		log.WithError(err).WithField(logfields.Object, logfields.Repr(svc)).Warn("DELETE /service/{id}: error deleting service")
		return api.Error(DeleteServiceIDFailureCode, err)
	}

	return NewDeleteServiceIDOK()
}

func (d *Daemon) svcDeleteByFrontendLocked(frontend *loadbalancer.L3n4Addr) error {
	svc, ok := d.loadBalancer.SVCMap[frontend.SHA256Sum()]
	if !ok {
		return fmt.Errorf("Service frontend not found %+v", frontend)
	}
	return d.svcDelete(&svc)
}

// Deletes a service by the frontend address
func (d *Daemon) svcDeleteByFrontend(frontend *loadbalancer.L3n4Addr) error {
	d.loadBalancer.BPFMapMU.Lock()
	defer d.loadBalancer.BPFMapMU.Unlock()

	return d.svcDeleteByFrontendLocked(frontend)
}

func (d *Daemon) svcDelete(svc *loadbalancer.LBSVC) error {
	if err := d.svcDeleteBPF(svc.FE); err != nil {
		return err
	}

	d.loadBalancer.DeleteService(svc)

	return nil
}

func (d *Daemon) svcDeleteBPF(svc loadbalancer.L3n4AddrID) error {
	var (
		errV2     error
		errLegacy error
	)

	errV2 = lbmap.DeleteServiceV2(svc, service.DeleteBackendID)
	if option.Config.EnableLegacyServices {
		errLegacy = d.svcDeleteBPFLegacy(svc)
	}

	if errV2 != nil || errLegacy != nil {
		return fmt.Errorf("Deleting service from BPF maps failed: %s (v2), %s (legacy)",
			errV2, errLegacy)
	}

	lbmap.DeleteServiceCache(svc)

	return nil
}

func (d *Daemon) svcDeleteBPFLegacy(svc loadbalancer.L3n4AddrID) error {
	log.WithField(logfields.ServiceName, svc.String()).Debug("deleting service from BPF maps")
	var svcKey lbmap.ServiceKey
	if !svc.IsIPv6() {
		svcKey = lbmap.NewService4Key(svc.IP, svc.Port, 0)
	} else {
		svcKey = lbmap.NewService6Key(svc.IP, svc.Port, 0)
	}

	svcKey.SetBackend(0)

	// Get count of backends from master.
	val, err := svcKey.Map().Lookup(svcKey.ToNetwork())
	if err != nil {
		return fmt.Errorf("key %s is not in lbmap", svcKey.ToNetwork())
	}

	vval := val.(lbmap.ServiceValue)
	numBackends := uint16(vval.GetCount())

	// ServiceKeys are unique by their slave number, which corresponds to the number of backends. Delete each of these.
	for i := numBackends; i > 0; i-- {
		var slaveKey lbmap.ServiceKey
		if !svc.IsIPv6() {
			slaveKey = lbmap.NewService4Key(svc.IP, svc.Port, i)
		} else {
			slaveKey = lbmap.NewService6Key(svc.IP, svc.Port, i)
		}
		log.WithFields(logrus.Fields{
			"idx.backend": i,
			"key":         slaveKey,
		}).Debug("deleting backend # for slave ServiceKey")
		if err := lbmap.DeleteService(slaveKey); err != nil {
			return fmt.Errorf("deleting service failed for %s: %s", slaveKey, err)

		}
	}

	log.WithField(logfields.ServiceID, svc.ID).Debug("done deleting service slaves, now deleting master service")
	if err := lbmap.DeleteService(svcKey); err != nil {
		return fmt.Errorf("deleting service failed for %s: %s", svcKey, err)
	}

	return nil
}

type getServiceID struct {
	daemon *Daemon
}

func NewGetServiceIDHandler(d *Daemon) GetServiceIDHandler {
	return &getServiceID{daemon: d}
}

func (h *getServiceID) Handle(params GetServiceIDParams) middleware.Responder {
	log.WithField(logfields.Params, logfields.Repr(params)).Debug("GET /service/{id} request")

	d := h.daemon

	d.loadBalancer.BPFMapMU.RLock()
	defer d.loadBalancer.BPFMapMU.RUnlock()

	if svc, ok := d.loadBalancer.SVCMapID[loadbalancer.ServiceID(params.ID)]; ok {
		return NewGetServiceIDOK().WithPayload(svc.GetModel())
	}
	return NewGetServiceIDNotFound()
}

// SVCGetBySHA256Sum returns a DeepCopied frontend with its backends.
func (d *Daemon) svcGetBySHA256Sum(feL3n4SHA256Sum string) *loadbalancer.LBSVC {
	d.loadBalancer.BPFMapMU.RLock()
	defer d.loadBalancer.BPFMapMU.RUnlock()

	v, ok := d.loadBalancer.SVCMap[feL3n4SHA256Sum]
	if !ok {
		return nil
	}
	// We will move the slice from the loadbalancer map which has a mutex. If
	// we don't copy the slice we might risk changing memory that should be
	// locked.
	beCpy := []loadbalancer.LBBackEnd{}
	for _, v := range v.BES {
		beCpy = append(beCpy, v)
	}
	return &loadbalancer.LBSVC{
		FE:  *v.FE.DeepCopy(),
		BES: beCpy,
	}
}

type getService struct {
	d *Daemon
}

func NewGetServiceHandler(d *Daemon) GetServiceHandler {
	return &getService{d: d}
}

func (h *getService) Handle(params GetServiceParams) middleware.Responder {
	log.WithField(logfields.Params, logfields.Repr(params)).Debug("GET /service request")
	list := h.d.GetServiceList()
	return NewGetServiceOK().WithPayload(list)
}

// RevNATAdd deep copies the given revNAT address to the cilium lbmap with the given id.
func (d *Daemon) RevNATAdd(id loadbalancer.ServiceID, revNAT loadbalancer.L3n4Addr) error {
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
func (d *Daemon) RevNATDelete(id loadbalancer.ServiceID) error {
	d.loadBalancer.BPFMapMU.Lock()
	defer d.loadBalancer.BPFMapMU.Unlock()

	revNAT, ok := d.loadBalancer.RevNATMap[id]
	if !ok {
		return nil
	}

	err := lbmap.DeleteRevNATBPF(id, revNAT.IsIPv6())

	// TODO should we delete even if err is != nil?
	if err == nil {
		delete(d.loadBalancer.RevNATMap, id)
	}
	return err
}

// RevNATDeleteAll deletes all RevNAT4, if IPv4 is enabled on daemon, and all RevNAT6
// stored on the daemon and on the bpf maps.
//
// Must be called with d.loadBalancer.BPFMapMU locked.
func (d *Daemon) RevNATDeleteAll() error {
	if option.Config.EnableIPv4 {
		if err := lbmap.RevNat4Map.DeleteAll(); err != nil {
			return err
		}
	}

	if option.Config.EnableIPv6 {
		if err := lbmap.RevNat6Map.DeleteAll(); err != nil {
			return err
		}
	}

	// TODO should we delete even if err is != nil?
	d.loadBalancer.RevNATMap = map[loadbalancer.ServiceID]loadbalancer.L3n4Addr{}
	return nil
}

// RevNATGet returns a DeepCopy of the revNAT found with the given ID or nil if not found.
func (d *Daemon) RevNATGet(id loadbalancer.ServiceID) (*loadbalancer.L3n4Addr, error) {
	d.loadBalancer.BPFMapMU.RLock()
	defer d.loadBalancer.BPFMapMU.RUnlock()

	revNAT, ok := d.loadBalancer.RevNATMap[id]
	if !ok {
		return nil, nil
	}
	return revNAT.DeepCopy(), nil
}

// RevNATDump dumps a DeepCopy of the cilium's loadbalancer.
func (d *Daemon) RevNATDump() ([]loadbalancer.L3n4AddrID, error) {
	dump := []loadbalancer.L3n4AddrID{}

	d.loadBalancer.BPFMapMU.RLock()
	defer d.loadBalancer.BPFMapMU.RUnlock()

	for k, v := range d.loadBalancer.RevNATMap {
		dump = append(dump, loadbalancer.L3n4AddrID{
			ID:       loadbalancer.ID(k),
			L3n4Addr: *v.DeepCopy(),
		})
	}

	return dump, nil
}

func openServiceMaps() error {
	if option.Config.EnableIPv6 {
		if option.Config.EnableLegacyServices {
			if _, err := lbmap.Service6Map.OpenOrCreate(); err != nil {
				return err
			}
			if _, err := lbmap.RRSeq6Map.OpenOrCreate(); err != nil {
				return err
			}
		} else {
			// Remove leftovers from previous installations
			if err := lbmap.Service6Map.UnpinIfExists(); err != nil {
				return err
			}
			if err := lbmap.RRSeq6Map.UnpinIfExists(); err != nil {
				return err
			}
		}
		if _, err := lbmap.Service6MapV2.OpenOrCreate(); err != nil {
			return err
		}
		if _, err := lbmap.Backend6Map.OpenOrCreate(); err != nil {
			return err
		}
		if _, err := lbmap.RevNat6Map.OpenOrCreate(); err != nil {
			return err
		}
		if _, err := lbmap.RRSeq6MapV2.OpenOrCreate(); err != nil {
			return err
		}
	}

	if option.Config.EnableIPv4 {
		if option.Config.EnableLegacyServices {
			if _, err := lbmap.Service4Map.OpenOrCreate(); err != nil {
				return err
			}
			if _, err := lbmap.RRSeq4Map.OpenOrCreate(); err != nil {
				return err
			}
		} else {
			// Remove leftovers from previous installations
			if err := lbmap.Service4Map.UnpinIfExists(); err != nil {
				return err
			}
			if err := lbmap.RRSeq4Map.UnpinIfExists(); err != nil {
				return err
			}
		}
		if _, err := lbmap.Service4MapV2.OpenOrCreate(); err != nil {
			return err
		}
		if _, err := lbmap.Backend4Map.OpenOrCreate(); err != nil {
			return err
		}
		if _, err := lbmap.RevNat4Map.OpenOrCreate(); err != nil {
			return err
		}
		if _, err := lbmap.RRSeq4MapV2.OpenOrCreate(); err != nil {
			return err
		}
	}

	return nil
}

// SyncLBMap syncs the bpf lbmap with the daemon's lb map. All bpf entries will overwrite
// the daemon's LB map. If the bpf lbmap entry has a different service ID than the
// KVStore's ID, that entry will be updated on the bpf map accordingly with the new ID
// retrieved from the KVStore.
func (d *Daemon) SyncLBMap() error {
	// Don't bother syncing if we are in dry mode.
	if option.Config.DryMode {
		return nil
	}

	log.Info("Restoring services from BPF maps...")

	d.loadBalancer.BPFMapMU.Lock()
	defer d.loadBalancer.BPFMapMU.Unlock()

	newSVCMapID := loadbalancer.SVCMapID{}
	newRevNATMap := loadbalancer.RevNATMap{}
	failedSyncSVC := []loadbalancer.LBSVC{}
	failedSyncRevNAT := map[loadbalancer.ServiceID]loadbalancer.L3n4Addr{}

	addSVC2BPFMap := func(oldID loadbalancer.ServiceID, svc loadbalancer.LBSVC) error {
		scopedLog := log.WithFields(logrus.Fields{
			logfields.ServiceID: oldID,
			logfields.SHA:       svc.FE.SHA256Sum(),
		})
		scopedLog.Debug("adding service ID with SHA")

		// check if the ID for revNat is present in the bpf map, update the
		// reverse nat key, delete the old one.
		revNAT, ok := newRevNATMap[oldID]
		if ok {
			scopedLog.Debug("Service ID is present in BPF map, updating revnat key")
			revNATK, revNATV := lbmap.L3n4Addr2RevNatKeynValue(
				loadbalancer.ServiceID(svc.FE.ID), revNAT)
			err := lbmap.UpdateRevNat(revNATK, revNATV)
			if err != nil {
				return fmt.Errorf("Unable to add revNAT: %s: %s."+
					" This entry will be removed from the bpf's LB map.", revNAT.String(), err)
			}

			// Remove the old entry from the bpf map.
			revNATK, _ = lbmap.L3n4Addr2RevNatKeynValue(oldID, revNAT)
			if err := lbmap.DeleteRevNat(revNATK); err != nil {
				scopedLog.WithError(err).Warn("Unable to remove old rev NAT entry")
			}

			scopedLog.Debug("deleting old ID from newRevNATMap")
			delete(newRevNATMap, oldID)

			log.WithFields(logrus.Fields{
				logfields.ServiceName: svc.FE.String(),
				"revNAT":              revNAT,
			}).Debug("adding service --> revNAT to newRevNATMap")
			newRevNATMap[loadbalancer.ServiceID(svc.FE.ID)] = revNAT
		}

		fe, besValues, err := lbmap.LBSVC2ServiceKeynValue(svc)
		if err != nil {
			return fmt.Errorf("Unable to create a BPF key and values for service FE: %s and backends: %+v. Error: %s."+
				" This entry will be removed from the bpf's LB map.", svc.FE.String(), svc.BES, err)
		}

		svcKeyV2, svcValuesV2, backendsV2, err := lbmap.LBSVC2ServiceKeynValuenBackendV2(&svc)
		if err != nil {
			return fmt.Errorf("Unable to create a BPF key and values for service v2 FE: %s and backends: %+v. Error: %s."+
				" This entry will be removed from the bpf's LB map.", svc.FE.String(), svc.BES, err)
		}

		err = d.addSVC2BPFMap(svc.FE, fe, besValues, svcKeyV2, svcValuesV2, backendsV2, false)
		if err != nil {
			return fmt.Errorf("Unable to add service FE: %s: %s."+
				" This entry will be removed from the bpf's LB map.", svc.FE.String(), err)
		}
		return nil
	}

	newSVCMap, newSVCList, lbmapDumpErrors := lbmap.DumpServiceMapsToUserspaceV2()
	for _, err := range lbmapDumpErrors {
		log.WithError(err).Warn("Unable to list services in services BPF map")
	}
	newRevNATMap, revNATMapDumpErrors := lbmap.DumpRevNATMapsToUserspace()
	for _, err := range revNATMapDumpErrors {
		log.WithError(err).Warn("Unable to list services in RevNat BPF map")
	}

	// Need to do this outside of parseSVCEntries to avoid deadlock, because we
	// are modifying the BPF maps, and calling Dump on a Map RLocks the maps.
	for _, svc := range newSVCList {
		scopedLog := log.WithField(logfields.Object, logfields.Repr(svc))
		kvL3n4AddrID, err := service.RestoreID(svc.FE.L3n4Addr, uint32(svc.FE.ID))
		if err != nil {
			scopedLog.WithError(err).Error("Unable to restore service ID")
			failedSyncSVC = append(failedSyncSVC, *svc)
			delete(newSVCMap, svc.Sha256)
			// Don't update the maps of services since the service failed to
			// sync.
			continue
		}

		// Mismatch detected between BPF Maps and KVstore, so we need to update
		// the ID in the BPF Maps to reflect the ID of the KVstore.
		if svc.FE.ID != kvL3n4AddrID.ID {
			scopedLog = scopedLog.WithField(logfields.ServiceID+".new", kvL3n4AddrID.ID)
			scopedLog.WithError(err).Warning("Service ID in BPF map is out of sync with KVStore. Acquired new ID")

			oldID := loadbalancer.ServiceID(svc.FE.ID)
			svc.FE.ID = kvL3n4AddrID.ID
			// If we cannot add the service to the BPF maps, update the list of
			// services that failed to sync.
			if err := addSVC2BPFMap(oldID, *svc); err != nil {
				scopedLog.WithError(err).Error("Unable to synchronize service to BPF map")

				failedSyncSVC = append(failedSyncSVC, *svc)
				delete(newSVCMap, svc.Sha256)

				revNAT, ok := newRevNATMap[loadbalancer.ServiceID(svc.FE.ID)]
				if ok {
					// Revert the old revNAT
					newRevNATMap[oldID] = revNAT
					failedSyncRevNAT[loadbalancer.ServiceID(svc.FE.ID)] = revNAT
					delete(newRevNATMap, loadbalancer.ServiceID(svc.FE.ID))
				}
				// Don't update the maps of services since the service failed to
				// sync.
				continue
			}
		}
		newSVCMapID[loadbalancer.ServiceID(svc.FE.ID)] = svc
	}

	// Clean services and rev nats from BPF maps that failed to be restored.
	for _, svc := range failedSyncSVC {
		if err := d.svcDeleteBPF(svc.FE); err != nil {
			log.WithError(err).WithField(logfields.Object, logfields.Repr(svc)).
				Warn("Unable to remove unrestorable service from BPF map")
		}
	}

	for id, revNAT := range failedSyncRevNAT {
		var revNATK lbmap.RevNatKey
		if !revNAT.IsIPv6() {
			revNATK = lbmap.NewRevNat4Key(uint16(id))
		} else {
			revNATK = lbmap.NewRevNat6Key(uint16(id))
		}

		if err := lbmap.DeleteRevNat(revNATK); err != nil {
			log.WithError(err).WithFields(logrus.Fields{
				logfields.ServiceID: id,
				"revNAT":            revNAT,
			}).Warn("Unable to clean rev NAT from BPF map")
		}
	}

	log.WithFields(logrus.Fields{
		"restoredServices": len(newSVCMap),
		"restoredRevNat":   len(newRevNATMap),
		"failedServices":   len(failedSyncSVC),
		"failedRevNat":     len(failedSyncRevNAT),
	}).Info("Restored services from BPF maps")

	d.loadBalancer.SVCMap = newSVCMap
	d.loadBalancer.SVCMapID = newSVCMapID
	d.loadBalancer.RevNATMap = newRevNATMap

	return nil
}

// syncLBMapsWithK8s ensures that the only contents of all BPF maps related to
// services (loadbalancer, RevNAT - for IPv4 and IPv6) are those that are
// sent to Cilium via K8s. This function is intended to be ran as part of a
// controller by the daemon when bootstrapping, although it could be called
// elsewhere it needed. Returns an error if any issues occur dumping BPF maps
// or deleting entries from BPF maps.
func (d *Daemon) syncLBMapsWithK8s() error {
	k8sDeletedServices := map[string]loadbalancer.L3n4AddrID{}
	alreadyChecked := map[string]struct{}{}

	// Maps service IDs to whether they are IPv6 (true) or IPv4 (false).
	k8sDeletedRevNATS := make(map[loadbalancer.ServiceID]bool)

	// Set of L3n4Addrs in string form for storage as a key in map.
	k8sServicesFrontendAddresses := d.k8sSvcCache.UniqueServiceFrontends()

	d.loadBalancer.BPFMapMU.Lock()
	defer d.loadBalancer.BPFMapMU.Unlock()

	log.Debugf("dumping BPF service maps to userspace")
	// At this point the creation of the v2 svc from the corresponding legacy
	// one has already happened, so it's safe to rely on the v2 when dumping
	_, newSVCList, lbmapDumpErrors := lbmap.DumpServiceMapsToUserspaceV2()

	if len(lbmapDumpErrors) > 0 {
		errorStrings := ""
		for _, err := range lbmapDumpErrors {
			errorStrings = fmt.Sprintf("%s, %s", err, errorStrings)
		}
		return fmt.Errorf("error(s): %s", errorStrings)
	}

	newRevNATMap, revNATMapDumpErrors := lbmap.DumpRevNATMapsToUserspace()
	if len(revNATMapDumpErrors) > 0 {
		errorStrings := ""
		for _, err := range revNATMapDumpErrors {
			errorStrings = fmt.Sprintf("%s, %s", err, errorStrings)
		}
		return fmt.Errorf("error(s): %s", errorStrings)
	}

	// Check whether services in service and revNAT BPF maps exist in the
	// in-memory K8s service maps. If not, mark them for deletion.
	for _, svc := range newSVCList {
		id := svc.FE.L3n4Addr.StringWithProtocol()
		if _, ok := alreadyChecked[id]; ok {
			continue
		}

		alreadyChecked[id] = struct{}{}

		scopedLog := log.WithFields(logrus.Fields{
			logfields.ServiceID: svc.FE.ID,
			logfields.L3n4Addr:  logfields.Repr(svc.FE.L3n4Addr)})

		if !k8sServicesFrontendAddresses.LooseMatch(svc.FE.L3n4Addr) {
			scopedLog.Warning("Deleting no longer present service in datapath")
			k8sDeletedServices[id] = svc.FE
			continue
		}

		scopedLog.Debug("Found matching k8s service for service in BPF map")
	}

	for serviceID, serviceInfo := range newRevNATMap {
		if _, ok := d.loadBalancer.RevNATMap[serviceID]; !ok {
			log.WithFields(logrus.Fields{
				logfields.ServiceID: serviceID,
				logfields.L3n4Addr:  logfields.Repr(serviceInfo)}).Debug("revNAT ID read from BPF maps is not managed by K8s; will delete it from BPF maps")
			// Map service ID to whether service is IPv4 or IPv6.
			if serviceInfo.IP.To4() == nil {
				k8sDeletedRevNATS[serviceID] = true
			} else {
				k8sDeletedRevNATS[serviceID] = false
			}
		}
	}

	bpfDeleteErrors := []error{}

	// Delete map entries from BPF which don't exist in list of Kubernetes
	// services.
	for _, svc := range k8sDeletedServices {
		svcLogger := log.WithField(logfields.Object, logfields.Repr(svc))
		svcLogger.Debug("removing service because it was not synced from Kubernetes")
		if err := d.svcDeleteBPF(svc); err != nil {
			bpfDeleteErrors = append(bpfDeleteErrors, err)
		}
	}

	for serviceID, isIPv6 := range k8sDeletedRevNATS {
		log.WithFields(logrus.Fields{logfields.ServiceID: serviceID, "isIPv6": isIPv6}).Debug("removing revNAT because it was not synced from Kubernetes")
		if err := lbmap.DeleteRevNATBPF(serviceID, isIPv6); err != nil {
			bpfDeleteErrors = append(bpfDeleteErrors, err)
		}
	}

	if len(bpfDeleteErrors) > 0 {
		bpfErrorsString := ""
		for _, err := range bpfDeleteErrors {
			bpfErrorsString = fmt.Sprintf("%s, %s", err, bpfErrorsString)
		}
		return fmt.Errorf("Errors deleting BPF map entries: %s", bpfErrorsString)
	}

	log.Debugf("successfully synced BPF loadbalancer and revNAT maps with in-memory Kubernetes service maps")

	return nil
}

func restoreBackendIDs() (map[lbmap.BackendAddrID]loadbalancer.BackendID, error) {
	lbBackends, err := lbmap.DumpBackendMapsToUserspace()
	if err != nil {
		return nil, fmt.Errorf("Unable to dump LB backend maps: %s", err)
	}

	restoredBackendIDs := map[lbmap.BackendAddrID]loadbalancer.BackendID{}

	for addrID, lbBackend := range lbBackends {
		err := service.RestoreBackendID(lbBackend.L3n4Addr, lbBackend.ID)
		if err != nil {
			return nil, err
		}
		restoredBackendIDs[addrID] = lbBackend.ID
	}

	log.WithField(logfields.BackendIDs, restoredBackendIDs).
		Debug("Restored backend IDs")

	return restoredBackendIDs, nil
}

func restoreServices() {
	before := time.Now()

	// Restore Backend IDs first, otherwise they can get taken by subsequent
	// calls to UpdateService
	restoredBackendIDs, err := restoreBackendIDs()
	if err != nil {
		log.WithError(err).Warning("Error occurred while restoring backend IDs")
	}
	lbmap.AddBackendIDsToCache(restoredBackendIDs)

	failed, restored, skipped, removed := 0, 0, 0, 0
	svcIDs := make(map[loadbalancer.ID]struct{})

	svcMapV2, _, errors := lbmap.DumpServiceMapsToUserspaceV2()
	for _, err := range errors {
		log.WithError(err).Warning("Error occured while dumping service v2 table from datapath")
	}
	svcMap := svcMapV2
	if option.Config.EnableLegacyServices {
		svcMap, _, errors = lbmap.DumpServiceMapsToUserspace()
		for _, err := range errors {
			log.WithError(err).Warning("Error occured while dumping service table from datapath")
		}
	}

	for feHash, svc := range svcMap {
		scopedLog := log.WithFields(logrus.Fields{
			logfields.ServiceID: svc.FE.ID,
			logfields.ServiceIP: svc.FE.L3n4Addr.String(),
		})
		// Services where the service ID was missing in the BPF map
		// cannot be restored
		if uint32(svc.FE.ID) == uint32(0) {
			skipped++
			continue
		}

		svcIDs[svc.FE.ID] = struct{}{}

		// The service ID can only be restored when global service IDs
		// are disabled. Global service IDs require kvstore access but
		// service load-balancing needs to be enabled before the
		// kvstore is guaranteed to be connected
		if option.Config.LBInterface == "" {
			_, err := service.RestoreID(svc.FE.L3n4Addr, uint32(svc.FE.ID))
			if err != nil {
				failed++
				scopedLog.WithError(err).Warning("Unable to restore service ID from datapath")
			} else {
				restored++
				scopedLog.Debug("Restored service ID from datapath")
			}
		}

		v2Exists := true
		if option.Config.EnableLegacyServices {
			_, v2Exists = svcMapV2[feHash]
		}

		// Restore the service cache to guarantee backend ordering
		// across restarts
		if err := lbmap.RestoreService(svc, v2Exists); err != nil {
			scopedLog.WithError(err).Warning("Unable to restore service in cache")
			failed++
			continue
		}

		if !option.Config.EnableLegacyServices {
			continue
		}

		// Create the svc v2 from the legacy one
		if !v2Exists {
			fe, besValues, err := lbmap.LBSVC2ServiceKeynValue(svc)
			if err != nil {
				failed++
				scopedLog.WithField(logfields.ServiceID, svc.FE.ID).WithError(err).
					WithError(err).Warning("Unable to convert service key and values v2")
				continue
			}
			// We restore only services which has the revNat enabled
			addRevNAT := true
			revNATID := int(svc.FE.ID)
			err = lbmap.UpdateService(fe, besValues, addRevNAT, revNATID, true,
				service.AcquireBackendID, service.DeleteBackendID)
			if err != nil {
				failed++
				scopedLog.WithField(logfields.ServiceID, svc.FE.ID).WithError(err).
					Warning("Unable to restore service v2")
			}
		}
	}

	// Delete v2 services which do not have the legacy equivalents. Can
	// happen after cilium-agent has been downgraded to < v1.5, some svc gets
	// removed, and then the agent upgraded again to >= v1.5 (observed on the CI).
	if option.Config.EnableLegacyServices {
		for feHash, svc := range svcMapV2 {
			if _, found := svcMap[feHash]; !found {
				// Remove revNAT if there is no restored service using it
				delRevNAT := true
				if _, found := svcIDs[svc.FE.ID]; found {
					delRevNAT = false
				}

				log.WithFields(logrus.Fields{
					logfields.ServiceID: svc.FE.ID,
					"delRevNAT":         delRevNAT,
				}).Debug("Deleting orphan service from BPF maps v2")

				if err := lbmap.DeleteOrphanServiceV2AndRevNAT(svc.FE, delRevNAT); err != nil {
					log.WithField(logfields.ServiceID, svc.FE.ID).WithError(err).
						Warning("Unable to remove orphan service v2")
				}
			}
		}
	}

	// Remove backend entries which are not used by any service.
	if errs := lbmap.DeleteOrphanBackends(service.DeleteBackendID); errs != nil && len(errs) > 0 {
		for _, err := range errs {
			log.WithError(err).Warning("Unable to remove orphan backend")
		}
	}

	log.WithFields(logrus.Fields{
		logfields.Duration: time.Now().Sub(before),
		"restored":         restored,
		"failed":           failed,
		"skipped":          skipped,
		"removed":          removed,
	}).Info("Restore service IDs from BPF maps")
}

// GetServiceList returns list of services
func (d *Daemon) GetServiceList() []*models.Service {
	list := []*models.Service{}

	d.loadBalancer.BPFMapMU.RLock()
	defer d.loadBalancer.BPFMapMU.RUnlock()

	for _, v := range d.loadBalancer.SVCMap {
		list = append(list, v.GetModel())
	}
	return list
}
