// Copyright 2016-2017 Authors of Cilium
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

	"github.com/cilium/cilium/api/v1/models"
	. "github.com/cilium/cilium/api/v1/server/restapi/service"
	"github.com/cilium/cilium/common/types"
	"github.com/cilium/cilium/pkg/apierror"
	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/logfields"
	"github.com/cilium/cilium/pkg/maps/lbmap"

	"github.com/go-openapi/runtime/middleware"
	log "github.com/sirupsen/logrus"
)

// addSVC2BPFMap adds the given bpf service to the bpf maps. If addRevNAT is set, adds the
// RevNAT value (feCilium.L3n4Addr) to the lb's RevNAT map for the given feCilium.ID.
func (d *Daemon) addSVC2BPFMap(feCilium types.L3n4AddrID, feBPF lbmap.ServiceKey,
	besBPF []lbmap.ServiceValue, addRevNAT bool) error {
	log.WithField(logfields.ServiceName, feCilium.String()).Debug("adding service to BPF maps")

	// Try to delete service before adding it and ignore errors as it might not exist.
	err := d.svcDeleteByFrontendLocked(&feCilium.L3n4Addr)
	if err != nil {
		log.WithError(err).WithField(logfields.ServiceName, feCilium.L3n4Addr.String()).Debug("error deleting service before adding it")
	}

	err = lbmap.AddSVC2BPFMap(feBPF, besBPF, addRevNAT, int(feCilium.ID))
	if err != nil {
		if addRevNAT {
			delete(d.loadBalancer.RevNATMap, feCilium.ID)
		}
		return err
	}

	if addRevNAT {
		log.WithField(logfields.ServiceName, feCilium.String()).Debug("adding service to RevNATMap")
		d.loadBalancer.RevNATMap[feCilium.ID] = *feCilium.L3n4Addr.DeepCopy()
	}
	return nil
}

// SVCAdd is the public method to add services. We assume the ID provided is not in
// sync with the KVStore. If that's the, case the service won't be used and an error is
// returned to the caller.
//
// Returns true if service was created.
func (d *Daemon) SVCAdd(feL3n4Addr types.L3n4AddrID, be []types.LBBackEnd, addRevNAT bool) (bool, error) {
	log.WithField(logfields.ServiceID, feL3n4Addr.String()).Debug("adding service")
	if feL3n4Addr.ID == 0 {
		return false, fmt.Errorf("invalid service ID 0")
	}
	// Check if the service is already registered with this ID.
	feAddr, err := GetL3n4AddrID(uint32(feL3n4Addr.ID))
	if err != nil {
		return false, fmt.Errorf("unable to get service %d: %s", feL3n4Addr.ID, err)
	}
	if feAddr == nil {
		feAddr, err = PutL3n4Addr(feL3n4Addr.L3n4Addr, uint32(feL3n4Addr.ID))
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
func (d *Daemon) svcAdd(feL3n4Addr types.L3n4AddrID, bes []types.LBBackEnd, addRevNAT bool) (bool, error) {
	log.WithFields(log.Fields{
		logfields.ServiceID: feL3n4Addr.String(),
		logfields.Object:    logfields.Repr(bes),
	}).Debug("adding service")

	// Move the slice to the loadbalancer map which has a mutex. If we don't
	// copy the slice we might risk changing memory that should be locked.
	beCpy := []types.LBBackEnd{}
	for _, v := range bes {
		beCpy = append(beCpy, v)
	}

	svc := types.LBSVC{
		FE:     feL3n4Addr,
		BES:    beCpy,
		Sha256: feL3n4Addr.L3n4Addr.SHA256Sum(),
	}

	fe, besValues, err := lbmap.LBSVC2ServiceKeynValue(svc)

	if err != nil {
		return false, err
	}

	d.loadBalancer.BPFMapMU.Lock()
	defer d.loadBalancer.BPFMapMU.Unlock()

	err = d.addSVC2BPFMap(feL3n4Addr, fe, besValues, addRevNAT)
	if err != nil {
		return false, err
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

	f, err := types.NewL3n4AddrFromModel(params.Config.FrontendAddress)
	if err != nil {
		return apierror.Error(PutServiceIDInvalidFrontendCode, err)
	}

	frontend := types.L3n4AddrID{
		L3n4Addr: *f,
		ID:       types.ServiceID(params.Config.ID),
	}

	backends := []types.LBBackEnd{}
	for _, v := range params.Config.BackendAddresses {
		b, err := types.NewLBBackEndFromBackendModel(v)
		if err != nil {
			return apierror.Error(PutServiceIDInvalidBackendCode, err)
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
		return apierror.Error(PutServiceIDFailureCode, err)
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

	svc, ok := d.loadBalancer.SVCMapID[types.ServiceID(params.ID)]

	if !ok {
		return NewDeleteServiceIDNotFound()
	}

	// FIXME: How to handle error?
	err := DeleteL3n4AddrIDByUUID(uint32(params.ID))

	if err != nil {
		log.WithError(err).Warn("error, DeleteL3n4AddrIDByUUID failed")
	}

	if err := h.d.svcDelete(svc); err != nil {
		log.WithError(err).WithField(logfields.Object, logfields.Repr(svc)).Warn("DELETE /service/{id}: error deleting service")
		return apierror.Error(DeleteServiceIDFailureCode, err)
	}

	return NewDeleteServiceIDOK()
}

func (d *Daemon) svcDeleteByFrontendLocked(frontend *types.L3n4Addr) error {
	svc, ok := d.loadBalancer.SVCMap[frontend.SHA256Sum()]
	if !ok {
		return fmt.Errorf("Service frontend not found %+v", frontend)
	}
	return d.svcDelete(&svc)
}

// Deletes a service by the frontend address
func (d *Daemon) svcDeleteByFrontend(frontend *types.L3n4Addr) error {
	d.loadBalancer.BPFMapMU.Lock()
	defer d.loadBalancer.BPFMapMU.Unlock()

	return d.svcDeleteByFrontendLocked(frontend)
}

func (d *Daemon) svcDelete(svc *types.LBSVC) error {
	if err := d.svcDeleteBPF(svc); err != nil {
		return err
	}
	d.loadBalancer.DeleteService(svc)
	return nil
}

func (d *Daemon) svcDeleteBPF(svc *types.LBSVC) error {
	log.WithField(logfields.ServiceName, svc.FE.String()).Debug("deleting service from BPF maps")
	var svcKey lbmap.ServiceKey
	if !svc.FE.IsIPv6() {
		svcKey = lbmap.NewService4Key(svc.FE.IP, svc.FE.Port, 0)
	} else {
		svcKey = lbmap.NewService6Key(svc.FE.IP, svc.FE.Port, 0)
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
		if !svc.FE.IsIPv6() {
			slaveKey = lbmap.NewService4Key(svc.FE.IP, svc.FE.Port, i)
		} else {
			slaveKey = lbmap.NewService6Key(svc.FE.IP, svc.FE.Port, i)
		}
		log.WithFields(log.Fields{
			"idx.backend": i,
			"key":         slaveKey,
		}).Debug("deleting backend # for slave ServiceKey")
		if err := lbmap.DeleteService(slaveKey); err != nil {
			return fmt.Errorf("deleting service failed for %s: %s", slaveKey, err)

		}
	}

	log.WithField(logfields.ServiceID, svc.FE.ID).Debug("done deleting service slaves, now deleting master service")
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

	if svc, ok := d.loadBalancer.SVCMapID[types.ServiceID(params.ID)]; ok {
		return NewGetServiceIDOK().WithPayload(svc.GetModel())
	}
	return NewGetServiceIDNotFound()
}

// SVCGetBySHA256Sum returns a DeepCopied frontend with its backends.
func (d *Daemon) svcGetBySHA256Sum(feL3n4SHA256Sum string) *types.LBSVC {
	d.loadBalancer.BPFMapMU.RLock()
	defer d.loadBalancer.BPFMapMU.RUnlock()

	v, ok := d.loadBalancer.SVCMap[feL3n4SHA256Sum]
	if !ok {
		return nil
	}
	// We will move the slice from the loadbalancer map which has a mutex. If
	// we don't copy the slice we might risk changing memory that should be
	// locked.
	beCpy := []types.LBBackEnd{}
	for _, v := range v.BES {
		beCpy = append(beCpy, v)
	}
	return &types.LBSVC{
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

	list := []*models.Service{}

	h.d.loadBalancer.BPFMapMU.RLock()
	defer h.d.loadBalancer.BPFMapMU.RUnlock()

	for _, v := range h.d.loadBalancer.SVCMap {
		list = append(list, v.GetModel())
	}

	return NewGetServiceOK().WithPayload(list)
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
//
// Must be called with d.loadBalancer.BPFMapMU locked.
func (d *Daemon) RevNATDeleteAll() error {

	if !d.conf.IPv4Disabled {
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
// the daemon's LB map. If the bpf lbmap entry has a different service ID than the
// KVStore's ID, that entry will be updated on the bpf map accordingly with the new ID
// retrieved from the KVStore.
func (d *Daemon) SyncLBMap() error {
	log.Debug("syncing BPF LBMaps with daemon's LB maps")
	d.loadBalancer.BPFMapMU.Lock()
	defer d.loadBalancer.BPFMapMU.Unlock()

	newSVCMap := types.SVCMap{}
	newSVCList := []*types.LBSVC{}
	newSVCMapID := types.SVCMapID{}
	newRevNATMap := types.RevNATMap{}
	failedSyncSVC := []types.LBSVC{}
	failedSyncRevNAT := map[types.ServiceID]types.L3n4Addr{}

	addSVC2BPFMap := func(oldID types.ServiceID, svc types.LBSVC) error {
		scopedLog := log.WithFields(log.Fields{
			logfields.ServiceID: oldID,
			logfields.SHA:       svc.FE.SHA256Sum(),
		})
		scopedLog.Debug("adding service ID with SHA")

		// check if the ID for revNat is present in the bpf map, update the
		// reverse nat key, delete the old one.
		revNAT, ok := newRevNATMap[oldID]
		if ok {
			scopedLog.Debug("Service ID is present in BPF map, updating revnat key")
			revNATK, revNATV := lbmap.L3n4Addr2RevNatKeynValue(svc.FE.ID, revNAT)
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

			log.WithFields(log.Fields{
				logfields.ServiceName: svc.FE.String(),
				"revNAT":              revNAT,
			}).Debug("adding service --> revNAT to newRevNATMap")
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

	parseSVCEntries := func(key bpf.MapKey, value bpf.MapValue) {
		svcKey := key.(lbmap.ServiceKey)
		//It's the frontend service so we don't add this one
		if svcKey.GetBackend() == 0 {
			return
		}
		svcValue := value.(lbmap.ServiceValue)

		scopedLog := log.WithFields(log.Fields{
			logfields.BPFMapKey:   svcKey,
			logfields.BPFMapValue: svcValue,
		})

		scopedLog.Debug("parsing service mapping")
		fe, be, err := lbmap.ServiceKeynValue2FEnBE(svcKey, svcValue)
		if err != nil {
			scopedLog.WithError(err).Error("SyncLBMap.parseSVCEntries")
			return
		}

		svc := newSVCMap.AddFEnBE(fe, be, svcKey.GetBackend())
		newSVCList = append(newSVCList, svc)
	}

	parseRevNATEntries := func(key bpf.MapKey, value bpf.MapValue) {
		revNatK := key.(lbmap.RevNatKey)
		revNatV := value.(lbmap.RevNatValue)
		scopedLog := log.WithFields(log.Fields{
			logfields.BPFMapKey:   revNatK,
			logfields.BPFMapValue: revNatV,
		})

		scopedLog.Debug("parsing BPF revNAT mapping")
		fe, err := lbmap.RevNatValue2L3n4AddrID(revNatK, revNatV)
		if err != nil {
			scopedLog.WithError(err).Error("SyncLBMap.parseRevNATEntries")
			return
		}
		newRevNATMap[fe.ID] = fe.L3n4Addr
	}

	if !d.conf.IPv4Disabled {
		// lbmap.RRSeq4Map is updated as part of Service4Map and does
		// not need separate dump.
		err := lbmap.Service4Map.Dump(lbmap.Service4DumpParser, parseSVCEntries)
		if err != nil {
			log.WithError(err).Warn("error dumping Service4Map")
		}
		err = lbmap.RevNat4Map.Dump(lbmap.RevNat4DumpParser, parseRevNATEntries)
		if err != nil {
			log.WithError(err).Warn("error dumping RevNat4Map")
		}
	}

	// lbmap.RRSeq6Map is updated as part of Service6Map and does not need
	// separate dump.
	err := lbmap.Service6Map.Dump(lbmap.Service6DumpParser, parseSVCEntries)
	if err != nil {
		log.WithError(err).Warn("error dumping Service6Map")
	}
	lbmap.RevNat6Map.Dump(lbmap.RevNat6DumpParser, parseRevNATEntries)
	if err != nil {
		log.WithError(err).Warn("error dumping RevNat6Map")
	}

	// Need to do this outside of parseSVCEntries to avoid deadlock, because we
	// are modifying the BPF maps, and calling Dump on a Map RLocks the maps.
	log.Debug("iterating over services read from BPF LB Map and seeing if they have the same ID set in the KV store")
	for _, svc := range newSVCList {
		// Check if the services read from the lbmap have the same ID set in the
		// KVStore.
		kvL3n4AddrID, err := PutL3n4Addr(svc.FE.L3n4Addr, 0)
		if err != nil {
			log.WithError(err).WithFields(log.Fields{
				logfields.L3n4Addr: logfields.Repr(svc.FE.L3n4Addr),
			}).Error("Unable to retrieve service ID from KVStore. This entry will be removed from the bpf's LB map.")
			failedSyncSVC = append(failedSyncSVC, *svc)
			delete(newSVCMap, svc.Sha256)
			// Don't update the maps of services since the service failed to
			// sync.
			continue
		}

		// Mismatch detected between BPF Maps and KVstore, so we need to update
		// the ID in the BPF Maps to reflect the ID of the KVstore.
		if svc.FE.ID != kvL3n4AddrID.ID {
			log.WithError(err).WithFields(log.Fields{
				logfields.ServiceID + ".old": svc.FE.ID,
				logfields.ServiceID + ".new": kvL3n4AddrID.ID,
			}).Info("Frontend service ID read from BPF map was out of sync with KVStore, got new ID")
			oldID := svc.FE.ID
			svc.FE.ID = kvL3n4AddrID.ID
			// If we cannot add the service to the BPF maps, update the list of
			// services that failed to sync.
			if err := addSVC2BPFMap(oldID, *svc); err != nil {
				log.WithError(err).WithFields(log.Fields{
					logfields.ServiceID + ".old": oldID,
					logfields.ServiceID + ".new": svc.FE.ID,
					logfields.Object:             logfields.Repr(svc),
				}).Error("SyncLBMap")

				failedSyncSVC = append(failedSyncSVC, *svc)
				delete(newSVCMap, svc.Sha256)

				revNAT, ok := newRevNATMap[svc.FE.ID]
				if ok {
					// Revert the old revNAT
					newRevNATMap[oldID] = revNAT
					failedSyncRevNAT[svc.FE.ID] = revNAT
					delete(newRevNATMap, svc.FE.ID)
				}
				// Don't update the maps of services since the service failed to
				// sync.
				continue
			}
		}
		newSVCMapID[svc.FE.ID] = svc
	}

	// Clean services and rev nats from BPF maps that failed to be restored.
	for _, svc := range failedSyncSVC {
		log.WithField(logfields.Object, logfields.Repr(svc.FE)).Debug("Unable to restore, so removing service")
		if err := d.svcDeleteBPF(&svc); err != nil {
			log.WithError(err).WithField(logfields.Object, logfields.Repr(svc.FE)).Warn("Unable to clean service from BPF map")
		}
	}

	for id, revNAT := range failedSyncRevNAT {
		log.WithFields(log.Fields{
			logfields.ServiceID: id,
			"revNAT":            revNAT,
		}).Debug("unable to restore, so removing revNAT")
		var revNATK lbmap.RevNatKey
		if !revNAT.IsIPv6() {
			revNATK = lbmap.NewRevNat4Key(uint16(id))
		} else {
			revNATK = lbmap.NewRevNat6Key(uint16(id))
		}

		if err := lbmap.DeleteRevNat(revNATK); err != nil {
			log.WithError(err).WithFields(log.Fields{
				logfields.ServiceID: id,
				"revNAT":            revNAT,
			}).Warn("Unable to clean rev NAT from BPF map")
		}
	}

	log.Debug("updating daemon's loadbalancer maps")
	d.loadBalancer.SVCMap = newSVCMap
	d.loadBalancer.SVCMapID = newSVCMapID
	d.loadBalancer.RevNATMap = newRevNATMap

	return nil
}
