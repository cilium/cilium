// Copyright 2019 Authors of Cilium
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
package svc

import (
	"fmt"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/counter"
	"github.com/cilium/cilium/pkg/k8s"
	lb "github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/maps/lbmap"
	"github.com/cilium/cilium/pkg/service"

	"github.com/sirupsen/logrus"
)

// Type is a type of a service.
type Type string

const (
	TypeClusterIP = Type("ClusterIP")
	TypeNodePort  = Type("NodePort")
)

var log = logging.DefaultLogger.WithField(logfields.LogSubsys, "svc")

type Service struct {
	lock.RWMutex

	svcByHash map[string]*lb.LBSVC
	svcByID   map[lb.ID]*lb.LBSVC

	backendRefCount counter.StringCounter
	backendByHash   map[string]*lb.LBBackEnd
}

// NewService creates a new instance of the service handler.
func NewService() *Service {
	return &Service{
		svcByHash:       map[string]*lb.LBSVC{},
		svcByID:         map[lb.ID]*lb.LBSVC{},
		backendRefCount: counter.StringCounter{},
		backendByHash:   map[string]*lb.LBBackEnd{},
	}
}

// InitMaps opens or creates BPF maps used by services.
//
// If restore is set to false, entries of the maps are removed.
func (s *Service) InitMaps(ipv6, ipv4, restore bool) error {
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
	}
	if ipv4 {
		toOpen = append(toOpen, lbmap.Service4MapV2, lbmap.Backend4Map, lbmap.RevNat4Map)
		if !restore {
			toDelete = append(toDelete, lbmap.Service4MapV2, lbmap.Backend4Map, lbmap.RevNat4Map)
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
// Returns true if the service hasn't existed before.
//
// TODO(brb) split into multiple smaller functions.
func (s *Service) UpsertService(
	frontend lb.L3n4AddrID, backends []lb.LBBackEnd, svcType Type) (bool, lb.ID, error) {

	s.Lock()
	defer s.Unlock()

	var err error
	new := false // service is new?
	ipv6 := frontend.IsIPv6()
	prevBackendCount := 0

	hash := frontend.SHA256Sum()
	svc, found := s.svcByHash[hash]
	if !found {
		new = true

		// Allocate service ID for the new service
		addrID, err := service.AcquireID(frontend.L3n4Addr, uint32(frontend.ID))
		if err != nil {
			return false, lb.ID(0),
				fmt.Errorf("Unable to allocate service ID %d for %q: %s",
					frontend.ID, frontend, err)
		}
		// TODO(brb) defer ReleaseID
		frontend.ID = addrID.ID

		backendsCopy := []lb.LBBackEnd{}
		for _, v := range backends {
			backendsCopy = append(backendsCopy, v)
		}
		svc = &lb.LBSVC{
			Sha256:        hash,
			FE:            frontend,
			BES:           backendsCopy,
			BackendByHash: map[string]*lb.LBBackEnd{},
			NodePort:      svcType == TypeNodePort,
		}
		s.svcByID[frontend.ID] = svc
		s.svcByHash[hash] = svc
	} else {
		// NOTE: We cannot restore svcType from BPF maps, so just set it
		//       each time (safe until GH#8700 has been fixed).
		svc.NodePort = svcType == TypeNodePort
		prevBackendCount = len(svc.BES)
	}

	// Update backends cache (allocates backend IDs for new backends)
	newBackends, obsoleteBackendIDs, err := s.updateBackendsCacheLocked(svc, backends)
	if err != nil {
		return false, lb.ID(0), err
	}

	// Add new backends to BPF maps
	for _, b := range newBackends {
		if err := lbmap.AddBackend(uint16(b.ID), b.L3n4Addr.IP, b.L3n4Addr.L4Addr.Port, ipv6); err != nil {
			return false, lb.ID(0), err
		}
	}

	// Insert service entries to BPF maps
	backendIDs := make([]uint16, len(backends))
	for i, b := range backends {
		backendIDs[i] = uint16(b.ID)
	}
	err = lbmap.UpsertService(
		uint16(svc.FE.ID), svc.FE.L3n4Addr.IP, svc.FE.L3n4Addr.L4Addr.Port,
		backendIDs, prevBackendCount,
		ipv6)
	if err != nil {
		return false, lb.ID(0), err
	}

	// Remove backends not used by any service
	for _, id := range obsoleteBackendIDs {
		if err := lbmap.DeleteBackendByID(uint16(id), ipv6); err != nil {
			log.WithError(err).WithField(logfields.BackendID, id).
				Warn("Failed to remove backend from maps")
		}
	}

	return new, lb.ID(svc.FE.ID), nil
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

	if svc, found := s.svcByHash[frontend.SHA256Sum()]; found {
		return true, s.deleteServiceLocked(svc)
	}

	return false, nil
}

// GetDeepCopyServiceByID returns a deep-copy of a service identified with
// the given ID.
//
// If a service cannot be found, returns false.
func (s *Service) GetDeepCopyServiceByID(id lb.ServiceID) (*lb.LBSVC, bool) {
	s.RLock()
	defer s.RUnlock()

	svc, found := s.svcByID[lb.ID(id)]
	if !found {
		return nil, false
	}

	return deepCopyLBSVC(svc), true
}

// GetDeepCopyServices returns a deep-copy of all installed services.
func (s *Service) GetDeepCopyServices() []*lb.LBSVC {
	s.RLock()
	defer s.RUnlock()

	svcs := make([]*lb.LBSVC, 0, len(s.svcByHash))
	for _, svc := range s.svcByHash {
		svcs = append(svcs, deepCopyLBSVC(svc))
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

	// Remove obsolete backends and release their IDs
	if err := s.deleteOrphanBackends(); err != nil {
		log.WithError(err).Warn("Failed to remove orphan backends")

	}

	return nil
}

// SyncWithK8s removes services which are not present in the given
// list of services retrieved from the k8s service cache.
//
// Safe to run multiple times.
func (s *Service) SyncWithK8s(k8sSVCFrontends k8s.FrontendList) error {
	s.Lock()
	defer s.Unlock()

	alreadyChecked := map[string]struct{}{}

	for hash, svc := range s.svcByHash {
		if _, found := alreadyChecked[hash]; found {
			continue
		}
		alreadyChecked[hash] = struct{}{}

		if !k8sSVCFrontends.LooseMatch(svc.FE.L3n4Addr) {
			log.WithFields(logrus.Fields{
				logfields.ServiceID: svc.FE.ID,
				logfields.L3n4Addr:  logfields.Repr(svc.FE.L3n4Addr)}).
				Warn("Deleting no longer present service")

			if err := s.deleteServiceLocked(svc); err != nil {
				return fmt.Errorf("Unable to remove service %+v: %s", svc, err)
			}
		}

	}

	return nil
}

func (s *Service) restoreBackendsLocked() error {
	backends, err := lbmap.DumpBackendMapsToUserspace()
	if err != nil {
		return fmt.Errorf("Unable to dump backend maps: %s", err)
	}

	for _, b := range backends {
		if err := service.RestoreBackendID(b.L3n4Addr, b.ID); err != nil {
			return fmt.Errorf("Unable to restore backend ID %d for %q: %s",
				b.ID, b.L3n4Addr, err)
		}

		hash := b.L3n4Addr.SHA256Sum()
		s.backendByHash[hash] = b
	}

	return nil
}

func (s *Service) deleteOrphanBackends() error {
	for hash, b := range s.backendByHash {
		if s.backendRefCount[hash] == 0 {
			service.DeleteBackendID(b.ID)
			if err := lbmap.DeleteBackendByID(uint16(b.ID), b.L3n4Addr.IsIPv6()); err != nil {
				return fmt.Errorf("Unable to remove backend %d from map: %s", b.ID, err)
			}
			delete(s.backendByHash, hash)
		}
	}

	return nil
}

func (s *Service) restoreServicesLocked() error {
	failed, restored := 0, 0

	_, svcs, errors := lbmap.DumpServiceMapsToUserspaceV2()
	for _, err := range errors {
		log.WithError(err).Warning("Error occurred while dumping service maps")
	}

	for i, svc := range svcs {
		scopedLog := log.WithFields(logrus.Fields{
			logfields.ServiceID: svc.FE.ID,
			logfields.ServiceIP: svc.FE.L3n4Addr.String(),
		})

		if _, err := service.RestoreID(svc.FE.L3n4Addr, uint32(svc.FE.ID)); err != nil {
			failed++
			scopedLog.WithError(err).Warning("Unable to restore service ID")
		}

		for _, backend := range svc.BES {
			s.backendRefCount.Add(backend.L3n4Addr.SHA256Sum())
		}

		s.svcByHash[svc.FE.SHA256Sum()] = svcs[i]
		s.svcByID[svc.FE.ID] = svcs[i]
		restored++
	}

	log.WithFields(logrus.Fields{
		"restored": restored,
		"failed":   failed,
	}).Info("Restored services from maps")

	return nil
}

func (s *Service) deleteServiceLocked(svc *lb.LBSVC) error {
	obsoleteBackendIDs := s.deleteBackendsFromCacheLocked(svc)

	if err := lbmap.DeleteService(svc.FE, len(svc.BES)); err != nil {
		return err
	}

	delete(s.svcByHash, svc.Sha256)
	delete(s.svcByID, svc.FE.ID)

	ipv6 := svc.FE.L3n4Addr.IsIPv6()
	for _, id := range obsoleteBackendIDs {
		if err := lbmap.DeleteBackendByID(uint16(id), ipv6); err != nil {
			return err
		}
	}
	if err := service.DeleteID(uint32(svc.FE.ID)); err != nil {
		return fmt.Errorf("Unable to release service ID %d: %s", svc.FE.ID, err)
	}

	return nil
}

func (s *Service) updateBackendsCacheLocked(svc *lb.LBSVC, backends []lb.LBBackEnd) ([]lb.LBBackEnd, []lb.BackendID, error) {
	obsoleteBackendIDs := []lb.BackendID{}
	newBackends := []lb.LBBackEnd{}
	backendSet := map[string]struct{}{}

	for i, backend := range backends {
		hash := backend.L3n4Addr.SHA256Sum()
		backendSet[hash] = struct{}{}

		if b, found := svc.BackendByHash[hash]; !found {
			if s.backendRefCount.Add(hash) {
				id, err := service.AcquireBackendID(backend.L3n4Addr)
				if err != nil {
					return nil, nil, fmt.Errorf("Unable to acquire backend ID for %q: %s",
						backend.L3n4Addr, err)
				}
				backends[i].ID = id
				newBackends = append(newBackends, backends[i])
				s.backendByHash[hash] = &backends[i]
			} else {
				backends[i].ID = s.backendByHash[hash].ID
			}
		} else {
			backends[i].ID = b.ID
		}
	}

	for _, backend := range svc.BES {
		hash := backend.L3n4Addr.SHA256Sum()
		if _, found := backendSet[hash]; !found {
			if s.backendRefCount.Delete(hash) {
				service.DeleteBackendID(backend.ID)
				delete(s.backendByHash, hash)
				obsoleteBackendIDs = append(obsoleteBackendIDs, backend.ID)
			}

			delete(svc.BackendByHash, hash)
		}
	}

	svc.BES = backends
	return newBackends, obsoleteBackendIDs, nil
}

func (s *Service) deleteBackendsFromCacheLocked(svc *lb.LBSVC) []lb.BackendID {
	obsoleteBackendIDs := []lb.BackendID{}

	for _, backend := range svc.BES {
		hash := backend.L3n4Addr.SHA256Sum()
		if s.backendRefCount.Delete(hash) {
			service.DeleteBackendID(backend.ID)
			obsoleteBackendIDs = append(obsoleteBackendIDs, backend.ID)
		}
	}

	return obsoleteBackendIDs
}

func deepCopyLBSVC(svc *lb.LBSVC) *lb.LBSVC {
	backends := make([]lb.LBBackEnd, len(svc.BES))
	for i, backend := range svc.BES {
		backends[i].L3n4Addr = *backend.DeepCopy()
		backends[i].ID = backend.ID
	}
	return &lb.LBSVC{
		FE:       *svc.FE.DeepCopy(),
		BES:      backends,
		NodePort: svc.NodePort,
	}
}
