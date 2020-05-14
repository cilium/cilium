// Copyright 2019-2020 Authors of Cilium
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

package service

import (
	"fmt"
	"net"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/counter"
	lb "github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/maps/lbmap"
	"github.com/cilium/cilium/pkg/metrics"
	monitorAPI "github.com/cilium/cilium/pkg/monitor/api"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/service/healthserver"

	"github.com/sirupsen/logrus"
)

var (
	updateMetric = metrics.ServicesCount.WithLabelValues("update")
	deleteMetric = metrics.ServicesCount.WithLabelValues("delete")
	addMetric    = metrics.ServicesCount.WithLabelValues("add")
)

// LBMap is the interface describing methods for manipulating service maps.
type LBMap interface {
	UpsertService(uint16, net.IP, uint16, []uint16, int, bool, lb.SVCType, bool, bool, uint32) error
	DeleteService(lb.L3n4AddrID, int) error
	AddBackend(uint16, net.IP, uint16, bool) error
	DeleteBackendByID(uint16, bool) error
	AddAffinityMatch(uint16, uint16) error
	DeleteAffinityMatch(uint16, uint16) error
	DumpServiceMaps() ([]*lb.SVC, []error)
	DumpBackendMaps() ([]*lb.Backend, error)
	DumpAffinityMatches() (lbmap.BackendIDByServiceIDSet, error)
}

// healthServer is used to manage HealtCheckNodePort listeners
type healthServer interface {
	UpsertService(svcID lb.ID, svcNS, svcName string, localEndpoints int, port uint16)
	DeleteService(svcID lb.ID)
}

// monitorNotify is used to send update notifications to the monitor
type monitorNotify interface {
	SendNotification(typ monitorAPI.AgentNotification, text string) error
}

type svcInfo struct {
	hash          string
	frontend      lb.L3n4AddrID
	backends      []lb.Backend
	backendByHash map[string]*lb.Backend

	svcType                   lb.SVCType
	svcTrafficPolicy          lb.SVCTrafficPolicy
	sessionAffinity           bool
	sessionAffinityTimeoutSec uint32
	svcHealthCheckNodePort    uint16
	svcName                   string
	svcNamespace              string

	restoredFromDatapath bool
}

func (svc *svcInfo) deepCopyToLBSVC() *lb.SVC {
	backends := make([]lb.Backend, len(svc.backends))
	for i, backend := range svc.backends {
		backends[i] = *backend.DeepCopy()
	}
	return &lb.SVC{
		Frontend:            *svc.frontend.DeepCopy(),
		Backends:            backends,
		Type:                svc.svcType,
		TrafficPolicy:       svc.svcTrafficPolicy,
		HealthCheckNodePort: svc.svcHealthCheckNodePort,
		Name:                svc.svcName,
		Namespace:           svc.svcNamespace,
	}
}

func (svc *svcInfo) requireNodeLocalBackends() bool {
	switch svc.svcType {
	case lb.SVCTypeNodePort, lb.SVCTypeLoadBalancer, lb.SVCTypeExternalIPs:
		return svc.svcTrafficPolicy == lb.SVCTrafficPolicyLocal
	case lb.SVCTypeHostPort:
		return false
	default:
		return false
	}
}

// Service is a service handler. Its main responsibility is to reflect
// service-related changes into BPF maps used by datapath BPF programs.
// The changes can be triggered either by k8s_watcher or directly by
// API calls to the /services endpoint.
type Service struct {
	lock.RWMutex

	svcByHash map[string]*svcInfo
	svcByID   map[lb.ID]*svcInfo

	backendRefCount counter.StringCounter
	backendByHash   map[string]*lb.Backend

	healthServer  healthServer
	monitorNotify monitorNotify

	lbmap LBMap
}

// NewService creates a new instance of the service handler.
func NewService(monitorNotify monitorNotify) *Service {
	return &Service{
		svcByHash:       map[string]*svcInfo{},
		svcByID:         map[lb.ID]*svcInfo{},
		backendRefCount: counter.StringCounter{},
		backendByHash:   map[string]*lb.Backend{},
		monitorNotify:   monitorNotify,
		healthServer:    healthserver.New(),
		lbmap:           &lbmap.LBBPFMap{},
	}
}

// InitMaps opens or creates BPF maps used by services.
//
// If restore is set to false, entries of the maps are removed.
func (s *Service) InitMaps(ipv6, ipv4, sockMaps, restore bool) error {
	s.Lock()
	defer s.Unlock()

	// The following two calls can be removed in v1.8+.
	if err := bpf.UnpinMapIfExists("cilium_lb6_rr_seq_v2"); err != nil {
		return nil
	}
	if err := bpf.UnpinMapIfExists("cilium_lb4_rr_seq_v2"); err != nil {
		return nil
	}

	toOpen := []*bpf.Map{}
	toDelete := []*bpf.Map{}
	if ipv6 {
		toOpen = append(toOpen, lbmap.Service6MapV2, lbmap.Backend6Map, lbmap.RevNat6Map)
		if !restore {
			toDelete = append(toDelete, lbmap.Service6MapV2, lbmap.Backend6Map, lbmap.RevNat6Map)
		}
		if sockMaps {
			if err := lbmap.CreateSockRevNat6Map(); err != nil {
				return err
			}
		}
	}
	if ipv4 {
		toOpen = append(toOpen, lbmap.Service4MapV2, lbmap.Backend4Map, lbmap.RevNat4Map)
		if !restore {
			toDelete = append(toDelete, lbmap.Service4MapV2, lbmap.Backend4Map, lbmap.RevNat4Map)
		}
		if sockMaps {
			if err := lbmap.CreateSockRevNat4Map(); err != nil {
				return err
			}
		}
	}

	for _, m := range toOpen {
		if _, err := m.OpenOrCreate(); err != nil {
			return err
		}
	}
	for _, m := range toDelete {
		if err := m.DeleteAll(); err != nil {
			return err
		}
	}

	return nil
}

// UpsertService inserts or updates the given service.
//
// The first return value is true if the service hasn't existed before.
func (s *Service) UpsertService(
	frontend lb.L3n4AddrID, backends []lb.Backend, svcType lb.SVCType,
	svcTrafficPolicy lb.SVCTrafficPolicy,
	sessionAffinity bool, sessionAffinityTimeoutSec uint32,
	svcHealthCheckNodePort uint16,
	svcName, svcNamespace string) (bool, lb.ID, error) {

	s.Lock()
	defer s.Unlock()

	scopedLog := log.WithFields(logrus.Fields{
		logfields.ServiceIP: frontend.L3n4Addr,
		logfields.Backends:  backends,

		logfields.ServiceType:                svcType,
		logfields.ServiceTrafficPolicy:       svcTrafficPolicy,
		logfields.ServiceHealthCheckNodePort: svcHealthCheckNodePort,
		logfields.ServiceName:                svcName,
		logfields.ServiceNamespace:           svcNamespace,

		logfields.SessionAffinity:        sessionAffinity,
		logfields.SessionAffinityTimeout: sessionAffinityTimeoutSec,
	})
	scopedLog.Debug("Upserting service")

	// If needed, create svcInfo and allocate service ID
	svc, new, prevSessionAffinity, err := s.createSVCInfoIfNotExist(frontend, svcType, svcTrafficPolicy,
		sessionAffinity, sessionAffinityTimeoutSec,
		svcHealthCheckNodePort, svcName, svcNamespace)
	if err != nil {
		return false, lb.ID(0), err
	}
	// TODO(brb) defer ServiceID release after we have a lbmap "rollback"
	scopedLog = scopedLog.WithField(logfields.ServiceID, svc.frontend.ID)
	scopedLog.Debug("Acquired service ID")

	onlyLocalBackends := svc.requireNodeLocalBackends()
	prevBackendCount := len(svc.backends)

	backendsCopy := []lb.Backend{}
	for _, b := range backends {
		// Services with trafficPolicy=Local may only use node-local backends.
		// We implement this by filtering out all backend IPs which are not a
		// local endpoint.
		if onlyLocalBackends && len(b.NodeName) > 0 && b.NodeName != nodeTypes.GetName() {
			continue
		}
		backendsCopy = append(backendsCopy, *b.DeepCopy())
	}

	// Update backends cache and allocate/release backend IDs
	newBackends, obsoleteBackendIDs, obsoleteSVCBackendIDs, err := s.updateBackendsCacheLocked(svc, backendsCopy)
	if err != nil {
		return false, lb.ID(0), err
	}

	// Update lbmaps (BPF service maps)
	if err = s.upsertServiceIntoLBMaps(svc, prevBackendCount, newBackends,
		obsoleteBackendIDs,
		prevSessionAffinity, obsoleteSVCBackendIDs,
		scopedLog); err != nil {

		return false, lb.ID(0), err
	}

	localBackendCount := len(backendsCopy)
	s.healthServer.UpsertService(lb.ID(svc.frontend.ID), svc.svcNamespace, svc.svcName,
		localBackendCount, svc.svcHealthCheckNodePort)

	if new {
		addMetric.Inc()
	} else {
		updateMetric.Inc()
	}

	s.notifyMonitorServiceUpsert(svc.frontend, svc.backends,
		svc.svcType, svc.svcTrafficPolicy, svc.svcName, svc.svcNamespace)

	return new, lb.ID(svc.frontend.ID), nil
}

// DeleteServiceByID removes a service identified by the given ID.
func (s *Service) DeleteServiceByID(id lb.ServiceID) (bool, error) {
	s.Lock()
	defer s.Unlock()

	if svc, found := s.svcByID[lb.ID(id)]; found {
		return true, s.deleteServiceLocked(svc)
	}

	return false, nil
}

// DeleteService removes the given service.
func (s *Service) DeleteService(frontend lb.L3n4Addr) (bool, error) {
	s.Lock()
	defer s.Unlock()

	if svc, found := s.svcByHash[frontend.Hash()]; found {
		return true, s.deleteServiceLocked(svc)
	}

	return false, nil
}

// GetDeepCopyServiceByID returns a deep-copy of a service identified with
// the given ID.
//
// If a service cannot be found, returns false.
func (s *Service) GetDeepCopyServiceByID(id lb.ServiceID) (*lb.SVC, bool) {
	s.RLock()
	defer s.RUnlock()

	svc, found := s.svcByID[lb.ID(id)]
	if !found {
		return nil, false
	}

	return svc.deepCopyToLBSVC(), true
}

// GetDeepCopyServices returns a deep-copy of all installed services.
func (s *Service) GetDeepCopyServices() []*lb.SVC {
	s.RLock()
	defer s.RUnlock()

	svcs := make([]*lb.SVC, 0, len(s.svcByHash))
	for _, svc := range s.svcByHash {
		svcs = append(svcs, svc.deepCopyToLBSVC())
	}

	return svcs
}

// RestoreServices restores services from BPF maps.
//
// The method should be called once before establishing a connectivity
// to kube-apiserver.
func (s *Service) RestoreServices() error {
	s.Lock()
	defer s.Unlock()

	// Restore backend IDs
	if err := s.restoreBackendsLocked(); err != nil {
		return err
	}

	// Restore service cache from BPF maps
	if err := s.restoreServicesLocked(); err != nil {
		return err
	}

	// Remove no longer existing affinity matches
	if option.Config.EnableSessionAffinity {
		if err := s.deleteOrphanAffinityMatchesLocked(); err != nil {
			return err
		}
	}

	// Remove obsolete backends and release their IDs
	if err := s.deleteOrphanBackends(); err != nil {
		log.WithError(err).Warn("Failed to remove orphan backends")

	}

	return nil
}

// deleteOrphanAffinityMatchesLocked removes affinity matches which point to
// non-existent svc ID and backend ID tuples.
func (s *Service) deleteOrphanAffinityMatchesLocked() error {
	matches, err := s.lbmap.DumpAffinityMatches()
	if err != nil {
		return err
	}

	toRemove := map[lb.ID][]lb.BackendID{}

	local := make(map[lb.ID]map[lb.BackendID]struct{}, len(s.svcByID))
	for id, svc := range s.svcByID {
		if !svc.sessionAffinity {
			continue
		}
		local[id] = make(map[lb.BackendID]struct{}, len(svc.backends))
		for _, backend := range svc.backends {
			local[id][backend.ID] = struct{}{}
		}
	}

	for svcID, backendIDs := range matches {
		for bID := range backendIDs {
			found := false
			if _, ok := local[lb.ID(svcID)]; ok {
				if _, ok := local[lb.ID(svcID)][lb.BackendID(bID)]; ok {
					found = true
				}
			}
			if !found {
				toRemove[lb.ID(svcID)] = append(toRemove[lb.ID(svcID)], lb.BackendID(bID))
			}
		}
	}

	for svcID, backendIDs := range toRemove {
		s.deleteBackendsFromAffinityMatchMap(svcID, backendIDs)
	}

	return nil
}

// SyncWithK8sFinished removes services which we haven't heard about during
// a sync period of cilium-agent's k8s service cache.
//
// The removal is based on an assumption that during the sync period
// UpsertService() is going to be called for each alive service.
func (s *Service) SyncWithK8sFinished() error {
	s.Lock()
	defer s.Unlock()

	for _, svc := range s.svcByHash {
		if svc.restoredFromDatapath {
			log.WithFields(logrus.Fields{
				logfields.ServiceID: svc.frontend.ID,
				logfields.L3n4Addr:  logfields.Repr(svc.frontend.L3n4Addr)}).
				Warn("Deleting no longer present service")

			if err := s.deleteServiceLocked(svc); err != nil {
				return fmt.Errorf("Unable to remove service %+v: %s", svc, err)
			}
		}
	}

	return nil
}

func (s *Service) createSVCInfoIfNotExist(
	frontend lb.L3n4AddrID,
	svcType lb.SVCType,
	svcTrafficPolicy lb.SVCTrafficPolicy,
	sessionAffinity bool, sessionAffinityTimeoutSec uint32,
	svcHealthCheckNodePort uint16,
	svcName, svcNamespace string,
) (*svcInfo, bool, bool, error) {

	prevSessionAffinity := false
	hash := frontend.Hash()
	svc, found := s.svcByHash[hash]
	if !found {
		// Allocate service ID for the new service
		addrID, err := AcquireID(frontend.L3n4Addr, uint32(frontend.ID))
		if err != nil {
			return nil, false, false,
				fmt.Errorf("Unable to allocate service ID %d for %v: %s",
					frontend.ID, frontend, err)
		}
		frontend.ID = addrID.ID

		svc = &svcInfo{
			hash:          hash,
			frontend:      frontend,
			backendByHash: map[string]*lb.Backend{},

			svcType:      svcType,
			svcName:      svcName,
			svcNamespace: svcNamespace,

			sessionAffinity:           sessionAffinity,
			sessionAffinityTimeoutSec: sessionAffinityTimeoutSec,

			svcTrafficPolicy:       svcTrafficPolicy,
			svcHealthCheckNodePort: svcHealthCheckNodePort,
		}
		s.svcByID[frontend.ID] = svc
		s.svcByHash[hash] = svc
	} else {
		prevSessionAffinity = svc.sessionAffinity
		svc.svcType = svcType
		svc.svcTrafficPolicy = svcTrafficPolicy
		svc.svcHealthCheckNodePort = svcHealthCheckNodePort
		svc.sessionAffinity = sessionAffinity
		svc.sessionAffinityTimeoutSec = sessionAffinityTimeoutSec
		// Name and namespace are both optional and intended for exposure via
		// API. They they are not part of any BPF maps and cannot be restored
		// from datapath.
		if svcName != "" {
			svc.svcName = svcName
		}
		if svcNamespace != "" {
			svc.svcNamespace = svcNamespace
		}
		// We have heard about the service from k8s, so unset the flag so that
		// SyncWithK8sFinished() won't consider the service obsolete, and thus
		// won't remove it.
		svc.restoredFromDatapath = false
	}

	return svc, !found, prevSessionAffinity, nil
}

func (s *Service) deleteBackendsFromAffinityMatchMap(svcID lb.ID, backendIDs []lb.BackendID) {
	log.WithFields(logrus.Fields{
		logfields.Backends:  backendIDs,
		logfields.ServiceID: svcID,
	}).Debug("Deleting backends from session affinity match")

	for _, bID := range backendIDs {
		if err := s.lbmap.DeleteAffinityMatch(uint16(svcID), uint16(bID)); err != nil {
			log.WithFields(logrus.Fields{
				logfields.BackendID: bID,
				logfields.ServiceID: svcID,
			}).WithError(err).Warn("Unable to remove entry from affinity match map")
		}
	}
}

func (s *Service) addBackendsToAffinityMatchMap(svcID lb.ID, backendIDs []lb.BackendID) {
	log.WithFields(logrus.Fields{
		logfields.Backends:  backendIDs,
		logfields.ServiceID: svcID,
	}).Debug("Adding backends to affinity match map")

	for _, bID := range backendIDs {
		if err := s.lbmap.AddAffinityMatch(uint16(svcID), uint16(bID)); err != nil {
			log.WithFields(logrus.Fields{
				logfields.BackendID: bID,
				logfields.ServiceID: svcID,
			}).WithError(err).Warn("Unable to add entry to affinity match map")
		}
	}
}

func (s *Service) upsertServiceIntoLBMaps(svc *svcInfo, prevBackendCount int,
	newBackends []lb.Backend, obsoleteBackendIDs []lb.BackendID,
	prevSessionAffinity bool, obsoleteSVCBackendIDs []lb.BackendID,
	scopedLog *logrus.Entry) error {

	ipv6 := svc.frontend.IsIPv6()

	var toDeleteAffinity, toAddAffinity []lb.BackendID

	// Update sessionAffinity
	if option.Config.EnableSessionAffinity {
		if prevSessionAffinity && !svc.sessionAffinity {
			// Remove backends from the affinity match because the svc's sessionAffinity
			// has been disabled
			toDeleteAffinity = make([]lb.BackendID, 0, len(obsoleteSVCBackendIDs)+len(svc.backends))
			toDeleteAffinity = append(toDeleteAffinity, obsoleteSVCBackendIDs...)
			for _, b := range svc.backends {
				toDeleteAffinity = append(toDeleteAffinity, b.ID)
			}
		} else if svc.sessionAffinity {
			toAddAffinity = make([]lb.BackendID, 0, len(svc.backends))
			for _, b := range svc.backends {
				toAddAffinity = append(toAddAffinity, b.ID)
			}
			if prevSessionAffinity {
				// Remove obsolete svc backends if previously the svc had the affinity enabled
				toDeleteAffinity = make([]lb.BackendID, 0, len(obsoleteSVCBackendIDs))
				for _, bID := range obsoleteSVCBackendIDs {
					toDeleteAffinity = append(toDeleteAffinity, bID)
				}
			}
		}

		s.deleteBackendsFromAffinityMatchMap(svc.frontend.ID, toDeleteAffinity)
		// New affinity matches (toAddAffinity) will be added after the new
		// backends have been added.
	}

	// Add new backends into BPF maps
	for _, b := range newBackends {
		scopedLog.WithFields(logrus.Fields{
			logfields.BackendID: b.ID,
			logfields.L3n4Addr:  b.L3n4Addr,
		}).Debug("Adding new backend")

		if err := s.lbmap.AddBackend(uint16(b.ID), b.L3n4Addr.IP,
			b.L3n4Addr.L4Addr.Port, ipv6); err != nil {
			return err
		}
	}

	// Upsert service entries into BPF maps
	backendIDs := make([]uint16, len(svc.backends))
	for i, b := range svc.backends {
		backendIDs[i] = uint16(b.ID)
	}

	svcType := svc.svcType
	// SVC of LoadBalancer type is identical to ExternalIP. However, currently
	// datapath does not support the LoadBalancer type, only ExternalIP. So,
	// for now set the ExternalIP type.
	if svcType == lb.SVCTypeLoadBalancer {
		svcType = lb.SVCTypeExternalIPs
	}

	err := s.lbmap.UpsertService(
		uint16(svc.frontend.ID), svc.frontend.L3n4Addr.IP,
		svc.frontend.L3n4Addr.L4Addr.Port,
		backendIDs, prevBackendCount,
		ipv6, svcType, svc.requireNodeLocalBackends(),
		svc.sessionAffinity, svc.sessionAffinityTimeoutSec)
	if err != nil {
		return err
	}

	if option.Config.EnableSessionAffinity {
		s.addBackendsToAffinityMatchMap(svc.frontend.ID, toAddAffinity)
	}

	// Remove backends not used by any service from BPF maps
	for _, id := range obsoleteBackendIDs {
		scopedLog.WithField(logfields.BackendID, id).
			Debug("Removing obsolete backend")

		if err := s.lbmap.DeleteBackendByID(uint16(id), ipv6); err != nil {
			log.WithError(err).WithField(logfields.BackendID, id).
				Warn("Failed to remove backend from maps")
		}
	}

	return nil
}

func (s *Service) restoreBackendsLocked() error {
	backends, err := s.lbmap.DumpBackendMaps()
	if err != nil {
		return fmt.Errorf("Unable to dump backend maps: %s", err)
	}

	for _, b := range backends {
		log.WithFields(logrus.Fields{
			logfields.BackendID: b.ID,
			logfields.L3n4Addr:  b.L3n4Addr.String(),
		}).Debug("Restoring backend")
		if err := RestoreBackendID(b.L3n4Addr, b.ID); err != nil {
			return fmt.Errorf("Unable to restore backend ID %d for %q: %s",
				b.ID, b.L3n4Addr, err)
		}

		hash := b.L3n4Addr.Hash()
		s.backendByHash[hash] = b
	}

	return nil
}

func (s *Service) deleteOrphanBackends() error {
	for hash, b := range s.backendByHash {
		if s.backendRefCount[hash] == 0 {
			log.WithField(logfields.BackendID, b.ID).
				Debug("Removing orphan backend")

			DeleteBackendID(b.ID)
			if err := s.lbmap.DeleteBackendByID(uint16(b.ID), b.L3n4Addr.IsIPv6()); err != nil {
				return fmt.Errorf("Unable to remove backend %d from map: %s", b.ID, err)
			}
			delete(s.backendByHash, hash)
		}
	}

	return nil
}

func (s *Service) restoreServicesLocked() error {
	failed, restored := 0, 0

	svcs, errors := s.lbmap.DumpServiceMaps()
	for _, err := range errors {
		log.WithError(err).Warning("Error occurred while dumping service maps")
	}

	for _, svc := range svcs {
		scopedLog := log.WithFields(logrus.Fields{
			logfields.ServiceID: svc.Frontend.ID,
			logfields.ServiceIP: svc.Frontend.L3n4Addr.String(),
		})
		scopedLog.Debug("Restoring service")

		if _, err := RestoreID(svc.Frontend.L3n4Addr, uint32(svc.Frontend.ID)); err != nil {
			failed++
			scopedLog.WithError(err).Warning("Unable to restore service ID")
		}

		newSVC := &svcInfo{
			hash:          svc.Frontend.Hash(),
			frontend:      svc.Frontend,
			backends:      svc.Backends,
			backendByHash: map[string]*lb.Backend{},
			// Correct traffic policy will be restored by k8s_watcher after k8s
			// service cache has been initialized
			svcType:          svc.Type,
			svcTrafficPolicy: svc.TrafficPolicy,

			sessionAffinity:           svc.SessionAffinity,
			sessionAffinityTimeoutSec: svc.SessionAffinityTimeoutSec,

			// Indicate that the svc was restored from the BPF maps, so that
			// SyncWithK8sFinished() could remove services which were restored
			// from the maps but not present in the k8sServiceCache (e.g. a svc
			// was deleted while cilium-agent was down).
			restoredFromDatapath: true,
		}

		for j, backend := range svc.Backends {
			hash := backend.L3n4Addr.Hash()
			s.backendRefCount.Add(hash)
			newSVC.backendByHash[hash] = &svc.Backends[j]
		}

		s.svcByHash[newSVC.hash] = newSVC
		s.svcByID[newSVC.frontend.ID] = newSVC
		restored++
	}

	log.WithFields(logrus.Fields{
		"restored": restored,
		"failed":   failed,
	}).Info("Restored services from maps")

	return nil
}

func (s *Service) deleteServiceLocked(svc *svcInfo) error {
	obsoleteBackendIDs := s.deleteBackendsFromCacheLocked(svc)

	scopedLog := log.WithFields(logrus.Fields{
		logfields.ServiceID: svc.frontend.ID,
		logfields.ServiceIP: svc.frontend.L3n4Addr,
		logfields.Backends:  svc.backends,
	})
	scopedLog.Debug("Deleting service")

	if err := s.lbmap.DeleteService(svc.frontend, len(svc.backends)); err != nil {
		return err
	}

	// Delete affinity matches
	if option.Config.EnableSessionAffinity && svc.sessionAffinity {
		backendIDs := make([]lb.BackendID, 0, len(svc.backends))
		for _, b := range svc.backends {
			backendIDs = append(backendIDs, b.ID)
		}
		s.deleteBackendsFromAffinityMatchMap(svc.frontend.ID, backendIDs)
	}

	delete(s.svcByHash, svc.hash)
	delete(s.svcByID, svc.frontend.ID)

	ipv6 := svc.frontend.L3n4Addr.IsIPv6()
	for _, id := range obsoleteBackendIDs {
		scopedLog.WithField(logfields.BackendID, id).
			Debug("Deleting obsolete backend")

		if err := s.lbmap.DeleteBackendByID(uint16(id), ipv6); err != nil {
			return err
		}
	}
	if err := DeleteID(uint32(svc.frontend.ID)); err != nil {
		return fmt.Errorf("Unable to release service ID %d: %s", svc.frontend.ID, err)
	}

	s.healthServer.DeleteService(lb.ID(svc.frontend.ID))

	deleteMetric.Inc()
	s.notifyMonitorServiceDelete(svc.frontend.ID)

	return nil
}

func (s *Service) updateBackendsCacheLocked(svc *svcInfo, backends []lb.Backend) (
	[]lb.Backend, []lb.BackendID, []lb.BackendID, error) {

	obsoleteBackendIDs := []lb.BackendID{}    // not used by any svc
	obsoleteSVCBackendIDs := []lb.BackendID{} // removed from the svc, but might be used by other svc
	newBackends := []lb.Backend{}             // previously not used by any svc
	backendSet := map[string]struct{}{}

	for i, backend := range backends {
		hash := backend.L3n4Addr.Hash()
		backendSet[hash] = struct{}{}

		if b, found := svc.backendByHash[hash]; !found {
			if s.backendRefCount.Add(hash) {
				id, err := AcquireBackendID(backend.L3n4Addr)
				if err != nil {
					return nil, nil, nil, fmt.Errorf("Unable to acquire backend ID for %q: %s",
						backend.L3n4Addr, err)
				}
				backends[i].ID = id
				newBackends = append(newBackends, backends[i])
				// TODO make backendByHash by value not by ref
				s.backendByHash[hash] = &backends[i]
			} else {
				backends[i].ID = s.backendByHash[hash].ID
			}
			svc.backendByHash[hash] = &backends[i]
		} else {
			backends[i].ID = b.ID
		}
	}

	for hash, backend := range svc.backendByHash {
		if _, found := backendSet[hash]; !found {
			obsoleteSVCBackendIDs = append(obsoleteSVCBackendIDs, backend.ID)
			if s.backendRefCount.Delete(hash) {
				DeleteBackendID(backend.ID)
				delete(s.backendByHash, hash)
				obsoleteBackendIDs = append(obsoleteBackendIDs, backend.ID)
			}
			delete(svc.backendByHash, hash)
		}
	}

	svc.backends = backends
	return newBackends, obsoleteBackendIDs, obsoleteSVCBackendIDs, nil
}

func (s *Service) deleteBackendsFromCacheLocked(svc *svcInfo) []lb.BackendID {
	obsoleteBackendIDs := []lb.BackendID{}

	for hash, backend := range svc.backendByHash {
		if s.backendRefCount.Delete(hash) {
			DeleteBackendID(backend.ID)
			obsoleteBackendIDs = append(obsoleteBackendIDs, backend.ID)
		}
	}

	return obsoleteBackendIDs
}

func (s *Service) notifyMonitorServiceUpsert(frontend lb.L3n4AddrID, backends []lb.Backend,
	svcType lb.SVCType, svcTrafficPolicy lb.SVCTrafficPolicy, svcName, svcNamespace string) {
	if s.monitorNotify == nil {
		return
	}

	id := uint32(frontend.ID)
	fe := monitorAPI.ServiceUpsertNotificationAddr{
		IP:   frontend.IP,
		Port: frontend.Port,
	}

	be := make([]monitorAPI.ServiceUpsertNotificationAddr, 0, len(backends))
	for _, backend := range backends {
		b := monitorAPI.ServiceUpsertNotificationAddr{
			IP:   backend.IP,
			Port: backend.Port,
		}
		be = append(be, b)
	}

	repr, err := monitorAPI.ServiceUpsertRepr(id, fe, be, string(svcType), string(svcTrafficPolicy), svcName, svcNamespace)
	if err == nil {
		s.monitorNotify.SendNotification(monitorAPI.AgentNotifyServiceUpserted, repr)
	}
}

func (s *Service) notifyMonitorServiceDelete(id lb.ID) {
	if s.monitorNotify != nil {
		if repr, err := monitorAPI.ServiceDeleteRepr(uint32(id)); err == nil {
			s.monitorNotify.SendNotification(monitorAPI.AgentNotifyServiceDeleted, repr)
		}
	}
}

// GetServiceNameByAddr returns namespace and name of the service with a given L3n4Addr. The third
// return value is set to true if and only if the service is found in the map.
func (s *Service) GetServiceNameByAddr(addr lb.L3n4Addr) (string, string, bool) {
	s.RLock()
	defer s.RUnlock()

	svc, found := s.svcByHash[addr.Hash()]
	if !found {
		return "", "", false
	}

	return svc.svcNamespace, svc.svcName, true
}
