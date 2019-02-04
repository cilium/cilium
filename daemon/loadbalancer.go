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
	besBPF []lbmap.ServiceValue, addRevNAT bool) error {
	log.WithField(logfields.ServiceName, feCilium.String()).Debug("adding service to BPF maps")

	if err := lbmap.UpdateService(feBPF, besBPF, addRevNAT, int(feCilium.ID)); err != nil {
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
	log.WithFields(logrus.Fields{
		logfields.ServiceID: feL3n4Addr.String(),
		logfields.Object:    logfields.Repr(bes),
	}).Debug("adding service")

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

	f, err := loadbalancer.NewL3n4AddrFromModel(params.Config.FrontendAddress)
	if err != nil {
		return api.Error(PutServiceIDInvalidFrontendCode, err)
	}

	frontend := loadbalancer.L3n4AddrID{
		L3n4Addr: *f,
		ID:       loadbalancer.ServiceID(params.Config.ID),
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
			ID:       k,
			L3n4Addr: *v.DeepCopy(),
		})
	}

	return dump, nil
}

func openServiceMaps() error {
	if option.Config.EnableIPv6 {
		if _, err := lbmap.Service6Map.OpenOrCreate(); err != nil {
			return err
		}
		if _, err := lbmap.RevNat6Map.OpenOrCreate(); err != nil {
			return err
		}
		if _, err := lbmap.RRSeq6Map.OpenOrCreate(); err != nil {
			return err
		}
	}

	if option.Config.EnableIPv4 {
		if _, err := lbmap.Service4Map.OpenOrCreate(); err != nil {
			return err
		}
		if _, err := lbmap.RevNat4Map.OpenOrCreate(); err != nil {
			return err
		}
		if _, err := lbmap.RRSeq4Map.OpenOrCreate(); err != nil {
			return err
		}
	}

	return nil
}

func restoreServiceIDs() {
	svcMap, _, errors := lbmap.DumpServiceMapsToUserspace(true)
	for _, err := range errors {
		log.WithError(err).Warning("Error occured while dumping service table from datapath")
	}

	for _, svc := range svcMap {
		// Services where the service ID was missing in the BPF map
		// cannot be restored
		if uint32(svc.FE.ID) == uint32(0) {
			continue
		}

		// The service ID can only be restored when global service IDs
		// are disabled. Global service IDs require kvstore access but
		// service load-balancing needs to be enabled before the
		// kvstore is guaranteed to be connected
		if option.Config.LBInterface == "" {
			scopedLog := log.WithFields(logrus.Fields{
				logfields.ServiceID: svc.FE.ID,
				logfields.ServiceIP: svc.FE.L3n4Addr.String(),
			})

			_, err := service.RestoreID(svc.FE.L3n4Addr, uint32(svc.FE.ID))
			if err != nil {
				scopedLog.WithError(err).Warning("Unable to restore service ID from datapath")
			} else {
				scopedLog.Info("Restored service ID from datapath")
			}
		}

		// Restore the service cache to guarantee backend ordering
		// across restarts
		if err := lbmap.RestoreService(svc); err != nil {
			log.WithError(err).Warning("Unable to restore service in cache")
		}
	}
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

	log.Info("Syncing BPF LBMaps with daemon's LB maps...")
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

			log.WithFields(logrus.Fields{
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

	newSVCMap, newSVCList, lbmapDumpErrors := lbmap.DumpServiceMapsToUserspace(false)
	for _, err := range lbmapDumpErrors {
		log.WithError(err).Warn("error dumping BPF map into userspace")
	}
	newRevNATMap, revNATMapDumpErrors := lbmap.DumpRevNATMapsToUserspace()
	for _, err := range revNATMapDumpErrors {
		log.WithError(err).Warn("error dumping BPF map into userspace")
	}

	// Need to do this outside of parseSVCEntries to avoid deadlock, because we
	// are modifying the BPF maps, and calling Dump on a Map RLocks the maps.
	log.Debug("iterating over services read from BPF LB Map and seeing if they have the same ID set in the KV store")
	for _, svc := range newSVCList {
		kvL3n4AddrID, err := service.RestoreID(svc.FE.L3n4Addr, uint32(svc.FE.ID))
		if err != nil {
			log.WithError(err).WithFields(logrus.Fields{
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
			log.WithError(err).WithFields(logrus.Fields{
				logfields.ServiceID + ".old": svc.FE.ID,
				logfields.ServiceID + ".new": kvL3n4AddrID.ID,
			}).Info("Frontend service ID read from BPF map was out of sync with KVStore, got new ID")
			oldID := svc.FE.ID
			svc.FE.ID = kvL3n4AddrID.ID
			// If we cannot add the service to the BPF maps, update the list of
			// services that failed to sync.
			if err := addSVC2BPFMap(oldID, *svc); err != nil {
				log.WithError(err).WithFields(logrus.Fields{
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
		if err := d.svcDeleteBPF(svc.FE); err != nil {
			log.WithError(err).WithField(logfields.Object, logfields.Repr(svc.FE)).Warn("Unable to clean service from BPF map")
		}
	}

	for id, revNAT := range failedSyncRevNAT {
		log.WithFields(logrus.Fields{
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
			log.WithError(err).WithFields(logrus.Fields{
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

// syncLBMapsWithK8s ensures that the only contents of all BPF maps related to
// services (loadbalancer, RevNAT - for IPv4 and IPv6) are those that are
// sent to Cilium via K8s. This function is intended to be ran as part of a
// controller by the daemon when bootstrapping, although it could be called
// elsewhere it needed. Returns an error if any issues occur dumping BPF maps
// or deleting entries from BPF maps.
func (d *Daemon) syncLBMapsWithK8s() error {
	k8sDeletedServices := map[string]loadbalancer.L3n4AddrID{}

	// Maps service IDs to whether they are IPv6 (true) or IPv4 (false).
	k8sDeletedRevNATS := make(map[loadbalancer.ServiceID]bool)

	// Set of L3n4Addrs in string form for storage as a key in map.
	k8sServicesFrontendAddresses := d.k8sSvcCache.UniqueServiceFrontends()

	d.loadBalancer.BPFMapMU.Lock()
	defer d.loadBalancer.BPFMapMU.Unlock()

	log.Debugf("dumping BPF service maps to userspace")
	_, newSVCList, lbmapDumpErrors := lbmap.DumpServiceMapsToUserspace(true)
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
		scopedLog := log.WithFields(logrus.Fields{
			logfields.ServiceID: svc.FE.ID,
			logfields.L3n4Addr:  logfields.Repr(svc.FE.L3n4Addr)})
		frontendAddress := svc.FE.L3n4Addr.StringWithProtocol()
		if _, ok := k8sServicesFrontendAddresses[frontendAddress]; !ok {
			scopedLog.Debug("service in BPF maps is not managed by K8s; will delete it from BPF maps")
			k8sDeletedServices[frontendAddress] = svc.FE
			continue
		}
		scopedLog.Debug("service from BPF maps is managed by K8s; will not delete it from BPF maps")
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
