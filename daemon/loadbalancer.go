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
	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/maps/lbmap"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/service"
	"github.com/cilium/cilium/pkg/svc"

	"github.com/go-openapi/runtime/middleware"
	"github.com/sirupsen/logrus"
)

// SVCAdd is the public method to add services. We assume the ID provided is not in
// sync with the KVStore. If that's the, case the service won't be used and an error is
// returned to the caller.
//
// Returns true if service was created.
func (d *Daemon) SVCAdd(feL3n4Addr loadbalancer.L3n4AddrID, be []loadbalancer.LBBackEnd) (bool, error) {
	log.WithField(logfields.ServiceID, feL3n4Addr.String()).Debug("adding service")
	if feL3n4Addr.ID == 0 {
		return false, fmt.Errorf("invalid service ID 0")
	}

	created, id, err := d.svc.UpsertService(feL3n4Addr, be, svc.TypeClusterIP)
	if err == nil && id != feL3n4Addr.ID {
		return false,
			fmt.Errorf("the service provided is already registered with ID %d, please use that ID instead of %d",
				id, feL3n4Addr.ID)
	}

	return created, err
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

	// FIXME
	// Add flag to indicate whether service should be registered in
	// global key value store

	if created, err := h.d.SVCAdd(frontend, backends); err != nil {
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

	found, err := h.d.svc.DeleteServiceByID(loadbalancer.ServiceID(params.ID))
	switch {
	case err != nil:
		log.WithError(err).WithField(logfields.ServiceID, params.ID).
			Warn("DELETE /service/{id}: error deleting service")
		return api.Error(DeleteServiceIDFailureCode, err)
	case !found:
		return NewDeleteServiceIDNotFound()
	default:
		return NewDeleteServiceIDOK()
	}
}

func (d *Daemon) svcDeleteBPF(svc loadbalancer.L3n4AddrID) error {
	if err := lbmap.DeleteServiceV2(svc, service.DeleteBackendID); err != nil {
		return fmt.Errorf("Deleting service from BPF maps failed: %s", err)
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

func openServiceMaps() error {
	// Removal of rr-seq maps can be removed in v1.8+.
	if err := bpf.UnpinMapIfExists("cilium_lb6_rr_seq_v2"); err != nil {
		return nil
	}
	if err := bpf.UnpinMapIfExists("cilium_lb4_rr_seq_v2"); err != nil {
		return nil
	}

	if option.Config.EnableIPv6 {
		if _, err := lbmap.Service6MapV2.OpenOrCreate(); err != nil {
			return err
		}
		if _, err := lbmap.Backend6Map.OpenOrCreate(); err != nil {
			return err
		}
		if _, err := lbmap.RevNat6Map.OpenOrCreate(); err != nil {
			return err
		}
	}

	if option.Config.EnableIPv4 {
		if _, err := lbmap.Service4MapV2.OpenOrCreate(); err != nil {
			return err
		}
		if _, err := lbmap.Backend4Map.OpenOrCreate(); err != nil {
			return err
		}
		if _, err := lbmap.RevNat4Map.OpenOrCreate(); err != nil {
			return err
		}
	}

	return nil
}

// SyncLBMap syncs the bpf lbmap with the daemon's lb map. All bpf entries will overwrite
// the daemon's LB map. If the bpf lbmap entry has a different service ID than the
// KVStore's ID (KVStore is currently not used for svc IDs), that entry will be removed.
func (d *Daemon) SyncLBMap() error {
	// Don't bother syncing if we are in dry mode.
	if option.Config.DryMode {
		return nil
	}

	log.Info("Restoring services from BPF maps...")

	d.loadBalancer.BPFMapMU.Lock()
	defer d.loadBalancer.BPFMapMU.Unlock()

	newSVCMapID := loadbalancer.SVCMapID{}
	failedSyncSVC := []loadbalancer.LBSVC{}

	newSVCMap, newSVCList, lbmapDumpErrors := lbmap.DumpServiceMapsToUserspaceV2()
	for _, err := range lbmapDumpErrors {
		log.WithError(err).Warn("Unable to list services in services BPF map")
	}

	// Need to do this outside of parseSVCEntries to avoid deadlock, because we
	// are modifying the BPF maps, and calling Dump on a Map RLocks the maps.
	for _, svc := range newSVCList {
		scopedLog := log.WithField(logfields.Object, logfields.Repr(svc))
		if _, err := service.RestoreID(svc.FE.L3n4Addr, uint32(svc.FE.ID)); err != nil {
			scopedLog.WithError(err).Error("Unable to restore service ID")
			failedSyncSVC = append(failedSyncSVC, *svc)
			delete(newSVCMap, svc.Sha256)
			// Don't update the maps of services since the service failed to
			// sync.
			continue
		}
		newSVCMapID[loadbalancer.ServiceID(svc.FE.ID)] = svc
	}

	for _, svc := range failedSyncSVC {
		if err := d.svcDeleteBPF(svc.FE); err != nil {
			log.WithError(err).WithField(logfields.Object, logfields.Repr(svc)).
				Warn("Unable to remove unrestorable service from BPF map")
		}
	}

	log.WithFields(logrus.Fields{
		"restoredServices": len(newSVCMap),
		"failedServices":   len(failedSyncSVC),
	}).Info("Restored services from BPF maps")

	d.loadBalancer.SVCMap = newSVCMap
	d.loadBalancer.SVCMapID = newSVCMapID

	return nil
}

// syncLBMapsWithK8s ensures that the only contents of all BPF maps related to
// services  are those that are sent to Cilium via K8s. This function is
// intended to be ran as part of a // controller by the daemon when bootstrapping,
// although it could be called elsewhere it needed. Returns an error if any issues
// occur dumping BPF maps or deleting entries from BPF maps.
func (d *Daemon) syncLBMapsWithK8s() error {
	k8sDeletedServices := map[string]loadbalancer.L3n4AddrID{}
	alreadyChecked := map[string]struct{}{}

	// Set of L3n4Addrs in string form for storage as a key in map.
	k8sServicesFrontendAddresses := d.k8sSvcCache.UniqueServiceFrontends()

	// NOTE: loadBalancer.BPFMapMU should be taken after k8sSvcCache.Mutex
	// has been released, otherwise a deadlock can happen: See GH-8764.
	d.loadBalancer.BPFMapMU.Lock()
	defer d.loadBalancer.BPFMapMU.Unlock()

	log.Debugf("dumping BPF service maps to userspace")
	_, newSVCList, lbmapDumpErrors := lbmap.DumpServiceMapsToUserspaceV2()

	if len(lbmapDumpErrors) > 0 {
		errorStrings := ""
		for _, err := range lbmapDumpErrors {
			errorStrings = fmt.Sprintf("%s, %s", err, errorStrings)
		}
		return fmt.Errorf("error(s): %s", errorStrings)
	}

	// Check whether services in service BPF maps exist in the in-memory
	// K8s service maps. If not, mark them for deletion.
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

	if len(bpfDeleteErrors) > 0 {
		bpfErrorsString := ""
		for _, err := range bpfDeleteErrors {
			bpfErrorsString = fmt.Sprintf("%s, %s", err, bpfErrorsString)
		}
		return fmt.Errorf("Errors deleting BPF map entries: %s", bpfErrorsString)
	}

	log.Debugf("successfully synced BPF loadbalancer maps with in-memory Kubernetes service maps")

	return nil
}

func restoreBackendIDs() (map[lbmap.BackendAddrID]lbmap.BackendKey, error) {
	lbBackends, err := lbmap.DumpBackendMapsToUserspace()
	if err != nil {
		return nil, fmt.Errorf("Unable to dump LB backend maps: %s", err)
	}

	restoredBackendIDs := map[lbmap.BackendAddrID]lbmap.BackendKey{}

	for addrID, lbBackend := range lbBackends {
		err := service.RestoreBackendID(lbBackend.L3n4Addr, lbBackend.ID)
		if err != nil {
			return nil, err
		}
		be, err := lbmap.LBBackEnd2Backend(*lbBackend)
		if err != nil {
			return nil, err
		}
		restoredBackendIDs[addrID] = be.GetKey()
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
		log.WithError(err).Warning("Error occurred while dumping service v2 table from datapath")
	}

	for _, svc := range svcMapV2 {
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
		_, err := service.RestoreID(svc.FE.L3n4Addr, uint32(svc.FE.ID))
		if err != nil {
			failed++
			scopedLog.WithError(err).Warning("Unable to restore service ID from datapath")
		} else {
			restored++
			scopedLog.Debug("Restored service ID from datapath")
		}

		// Restore the service cache to guarantee backend ordering
		// across restarts
		if err := lbmap.RestoreService(svc); err != nil {
			scopedLog.WithError(err).Warning("Unable to restore service in cache")
			failed++
			continue
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
