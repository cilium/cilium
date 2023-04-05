// SPDX-License-Identifier: Apache-2.0
// Copyright 2019-2020 Authors of Cilium

package service

import (
	"fmt"
	"net"
	"sync/atomic"
	"time"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/cidr"
	"github.com/cilium/cilium/pkg/counter"
	datapathOpt "github.com/cilium/cilium/pkg/datapath/option"
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
	"go.uber.org/multierr"
)

var (
	updateMetric = metrics.ServicesCount.WithLabelValues("update")
	deleteMetric = metrics.ServicesCount.WithLabelValues("delete")
	addMetric    = metrics.ServicesCount.WithLabelValues("add")
)

// LBMap is the interface describing methods for manipulating service maps.
type LBMap interface {
	UpsertService(*lbmap.UpsertServiceParams) error
	UpsertMaglevLookupTable(uint16, map[string]lb.BackendID, bool) error
	IsMaglevLookupTableRecreated(bool) bool
	DeleteService(lb.L3n4AddrID, int, bool) error
	AddBackend(lb.BackendID, net.IP, uint16, bool) error
	DeleteBackendByID(lb.BackendID, bool) error
	AddAffinityMatch(uint16, lb.BackendID) error
	DeleteAffinityMatch(uint16, lb.BackendID) error
	UpdateSourceRanges(uint16, []*cidr.CIDR, []*cidr.CIDR, bool) error
	DumpServiceMaps() ([]*lb.SVC, []error)
	DumpBackendMaps() ([]*lb.Backend, error)
	DumpAffinityMatches() (lbmap.BackendIDByServiceIDSet, error)
	DumpSourceRanges(bool) (lbmap.SourceRangeSetByServiceID, error)
}

// healthServer is used to manage HealtCheckNodePort listeners
type healthServer interface {
	UpsertService(svcID lb.ID, svcNS, svcName string, localEndpoints int, port uint16)
	DeleteService(svcID lb.ID)
}

// monitorNotify is used to send update notifications to the monitor
type monitorNotify interface {
	SendNotification(msg monitorAPI.AgentNotifyMessage) error
}

type svcInfo struct {
	hash                string
	frontend            lb.L3n4AddrID
	backends            []lb.Backend
	activeBackendsCount int // Non-terminating backends count
	backendByHash       map[string]*lb.Backend

	svcType                   lb.SVCType
	svcTrafficPolicy          lb.SVCTrafficPolicy
	sessionAffinity           bool
	sessionAffinityTimeoutSec uint32
	svcHealthCheckNodePort    uint16
	svcName                   string
	svcNamespace              string
	loadBalancerSourceRanges  []*cidr.CIDR

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

// requireNodeLocalBackends returns true if the frontend service traffic policy
// is lb.SVCTrafficPolicyLocal and whether only local backends need to be filtered for the
// given frontend.
func (svc *svcInfo) requireNodeLocalBackends(frontend lb.L3n4AddrID) (bool, bool) {
	switch svc.svcType {
	case lb.SVCTypeLocalRedirect:
		return false, true
	case lb.SVCTypeNodePort, lb.SVCTypeLoadBalancer, lb.SVCTypeExternalIPs:
		if svc.svcTrafficPolicy == lb.SVCTrafficPolicyLocal {
			return true, frontend.Scope == lb.ScopeExternal
		}
		fallthrough
	default:
		return false, false
	}
}

func (svc *svcInfo) useMaglev() bool {
	return option.Config.NodePortAlg == option.NodePortAlgMaglev &&
		((svc.svcType == lb.SVCTypeNodePort && !isWildcardAddr(svc.frontend)) ||
			svc.svcType == lb.SVCTypeExternalIPs ||
			svc.svcType == lb.SVCTypeLoadBalancer ||
			// Provision the Maglev LUT for ClusterIP only if ExternalClusterIP is enabled
			// because ClusterIP can also be accessed from outside with this setting.
			// We don't do it unconditionally to avoid increasing memory footprint.
			(option.Config.ExternalClusterIP && svc.svcType == lb.SVCTypeClusterIP))
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

	lbmap         LBMap
	lastUpdatedTs atomic.Value
}

// NewService creates a new instance of the service handler.
func NewService(monitorNotify monitorNotify) *Service {

	var localHealthServer healthServer
	if option.Config.EnableHealthCheckNodePort {
		localHealthServer = healthserver.New()
	}

	maglev := option.Config.NodePortAlg == option.NodePortAlgMaglev
	maglevTableSize := option.Config.MaglevTableSize

	svc := &Service{
		svcByHash:       map[string]*svcInfo{},
		svcByID:         map[lb.ID]*svcInfo{},
		backendRefCount: counter.StringCounter{},
		backendByHash:   map[string]*lb.Backend{},
		monitorNotify:   monitorNotify,
		healthServer:    localHealthServer,
		lbmap:           lbmap.New(maglev, maglevTableSize),
	}
	svc.lastUpdatedTs.Store(time.Now())
	return svc
}

func (s *Service) GetLastUpdatedTs() time.Time {
	if val := s.lastUpdatedTs.Load(); val != nil {
		ts, ok := val.(time.Time)
		if ok {
			return ts
		}
	}
	return time.Now()
}

func (s *Service) GetCurrentTs() time.Time {
	return time.Now()
}

func (s *Service) populateBackendMapV2FromV1(ipv4, ipv6 bool) error {
	const (
		v4 = "ipv4"
		v6 = "ipv6"
	)

	var (
		err   error
		v1Map *bpf.Map
	)

	enabled := map[string]bool{v4: ipv4, v6: ipv6}

	for v, e := range enabled {
		if !e {
			continue
		}

		copyBackendEntries := func(key bpf.MapKey, value bpf.MapValue) {
			var (
				v2Map        *bpf.Map
				v2BackendKey lbmap.BackendKey
			)

			if v == v4 {
				backendKey := key.(lbmap.BackendKey)
				v2Map = lbmap.Backend4MapV2
				v2BackendKey = lbmap.NewBackend4KeyV2(backendKey.GetID())
			} else {
				backendKey := key.(lbmap.BackendKey)
				v2Map = lbmap.Backend6MapV2
				v2BackendKey = lbmap.NewBackend6KeyV2(backendKey.GetID())
			}

			err := v2Map.Update(v2BackendKey, value.DeepCopyMapValue())
			if err != nil {
				log.WithError(err).WithField(logfields.BPFMapName, v2Map.Name()).Warn("Error updating map")
			}
		}

		if v == v4 {
			v1Map = lbmap.Backend4Map
		} else {
			v1Map = lbmap.Backend6Map
		}

		err = v1Map.DumpWithCallback(copyBackendEntries)
		if err != nil {
			return fmt.Errorf("Unable to populate %s: %w", v1Map.Name(), err)
		}

		// V1 backend map will be removed from bpffs at this point,
		// the map will be actually removed once the last program
		// referencing it has been removed.
		err = v1Map.Close()
		if err != nil {
			log.WithError(err).WithField(logfields.BPFMapName, v1Map.Name()).Warn("Error closing map")
		}

		err = v1Map.Unpin()
		if err != nil {
			log.WithError(err).WithField(logfields.BPFMapName, v1Map.Name()).Warn("Error unpinning map")
		}

	}
	return nil
}

// InitMaps opens or creates BPF maps used by services.
//
// If restore is set to false, entries of the maps are removed.
func (s *Service) InitMaps(ipv6, ipv4, sockMaps, restore bool) error {
	s.Lock()
	defer s.Unlock()

	var (
		v1BackendMapExistsV4 bool
		v1BackendMapExistsV6 bool
	)

	toOpen := []*bpf.Map{}
	toDelete := []*bpf.Map{}
	if ipv6 {
		toOpen = append(toOpen, lbmap.Service6MapV2, lbmap.Backend6MapV2, lbmap.RevNat6Map)
		if !restore {
			toDelete = append(toDelete, lbmap.Service6MapV2, lbmap.Backend6MapV2, lbmap.RevNat6Map)
		}
		if sockMaps {
			if err := lbmap.CreateSockRevNat6Map(); err != nil {
				return err
			}
		}
		v1BackendMapExistsV6 = lbmap.Backend6Map.Open() == nil
	}
	if ipv4 {
		toOpen = append(toOpen, lbmap.Service4MapV2, lbmap.Backend4MapV2, lbmap.RevNat4Map)
		if !restore {
			toDelete = append(toDelete, lbmap.Service4MapV2, lbmap.Backend4MapV2, lbmap.RevNat4Map)
		}
		if sockMaps {
			if err := lbmap.CreateSockRevNat4Map(); err != nil {
				return err
			}
		}
		v1BackendMapExistsV4 = lbmap.Backend4Map.Open() == nil
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

	if v1BackendMapExistsV4 || v1BackendMapExistsV6 {
		log.Info("Backend map v1 exists. Migrating entries to backend map v2.")
		if err := s.populateBackendMapV2FromV1(v1BackendMapExistsV4, v1BackendMapExistsV6); err != nil {
			log.WithError(err).Warn("Error populating V2 map from V1 map, might interrupt existing connections during upgrade")
		}
	}

	return nil
}

// UpsertService inserts or updates the given service.
//
// The first return value is true if the service hasn't existed before.
func (s *Service) UpsertService(params *lb.SVC) (bool, lb.ID, error) {
	s.Lock()
	defer s.Unlock()

	scopedLog := log.WithFields(logrus.Fields{
		logfields.ServiceIP: params.Frontend.L3n4Addr,
		logfields.Backends:  params.Backends,

		logfields.ServiceType:                params.Type,
		logfields.ServiceTrafficPolicy:       params.TrafficPolicy,
		logfields.ServiceHealthCheckNodePort: params.HealthCheckNodePort,
		logfields.ServiceName:                params.Name,
		logfields.ServiceNamespace:           params.Namespace,

		logfields.SessionAffinity:        params.SessionAffinity,
		logfields.SessionAffinityTimeout: params.SessionAffinityTimeoutSec,

		logfields.LoadBalancerSourceRanges: params.LoadBalancerSourceRanges,
	})
	scopedLog.Debug("Upserting service")

	if !option.Config.EnableSVCSourceRangeCheck &&
		len(params.LoadBalancerSourceRanges) != 0 {
		scopedLog.Warnf("--%s is disabled, ignoring loadBalancerSourceRanges",
			option.EnableSVCSourceRangeCheck)
	}

	ipv6Svc := params.Frontend.IsIPv6()
	if ipv6Svc && !option.Config.EnableIPv6 {
		err := fmt.Errorf("Unable to upsert service %s as IPv6 is disabled", params.Frontend.L3n4Addr.String())
		return false, lb.ID(0), err
	}
	if !ipv6Svc && !option.Config.EnableIPv4 {
		err := fmt.Errorf("Unable to upsert service %s as IPv4 is disabled", params.Frontend.L3n4Addr.String())
		return false, lb.ID(0), err
	}

	// If needed, create svcInfo and allocate service ID
	svc, new, prevSessionAffinity, prevLoadBalancerSourceRanges, err :=
		s.createSVCInfoIfNotExist(params)
	if err != nil {
		return false, lb.ID(0), err
	}
	// TODO(brb) defer ServiceID release after we have a lbmap "rollback"
	scopedLog = scopedLog.WithField(logfields.ServiceID, svc.frontend.ID)
	scopedLog.Debug("Acquired service ID")

	onlyLocalBackends, filterBackends := svc.requireNodeLocalBackends(params.Frontend)
	prevActiveBackendCount := svc.activeBackendsCount

	backendsCopy := []lb.Backend{}
	for _, b := range params.Backends {
		// Local redirect services or services with trafficPolicy=Local may
		// only use node-local backends for external scope. We implement this by
		// filtering out all backend IPs which are not a local endpoint.
		if filterBackends && len(b.NodeName) > 0 && b.NodeName != nodeTypes.GetName() {
			continue
		}
		backendsCopy = append(backendsCopy, *b.DeepCopy())
	}

	// TODO (Aditi) When we filter backends for LocalRedirect service, there
	// might be some backend pods with active connections. We may need to
	// defer filtering the backends list (thereby defer redirecting traffic)
	// in such cases. GH #12859
	// Update backends cache and allocate/release backend IDs
	newBackends, obsoleteBackendIDs, obsoleteSVCBackendIDs, err :=
		s.updateBackendsCacheLocked(svc, backendsCopy)
	if err != nil {
		return false, lb.ID(0), err
	}

	// Update lbmaps (BPF service maps)
	if err = s.upsertServiceIntoLBMaps(svc, onlyLocalBackends, prevActiveBackendCount,
		newBackends, obsoleteBackendIDs, prevSessionAffinity, prevLoadBalancerSourceRanges,
		obsoleteSVCBackendIDs, scopedLog); err != nil {

		return false, lb.ID(0), err
	}

	// Only add a HealthCheckNodePort server if this is a service which may
	// only contain local backends (i.e. it has externalTrafficPolicy=Local)
	if option.Config.EnableHealthCheckNodePort {
		if onlyLocalBackends && filterBackends {
			var activeBackends int
			for _, b := range backendsCopy {
				if !b.Terminating {
					activeBackends++
				}
			}

			s.healthServer.UpsertService(lb.ID(svc.frontend.ID), svc.svcNamespace, svc.svcName,
				activeBackends, svc.svcHealthCheckNodePort)
		} else if svc.svcHealthCheckNodePort == 0 {
			// Remove the health check server in case this service used to have
			// externalTrafficPolicy=Local with HealthCheckNodePort in the previous
			// version, but not anymore.
			s.healthServer.DeleteService(lb.ID(svc.frontend.ID))
		}
	}

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
// It first restores all the service entries, followed by backend entries.
// In the process, it deletes any duplicate backend entries that were leaked, and
// are not referenced by any service entries.
//
// The method should be called once before establishing a connectivity
// to kube-apiserver.
func (s *Service) RestoreServices() error {
	s.Lock()
	defer s.Unlock()
	var errs error
	backendsById := make(map[lb.BackendID]struct{})

	// Restore service cache from BPF maps
	if err := s.restoreServicesLocked(backendsById); err != nil {
		errs = multierr.Append(errs,
			fmt.Errorf("error while restoring services: %w", err))
	}

	// Restore backend IDs
	if err := s.restoreBackendsLocked(backendsById); err != nil {
		errs = multierr.Append(errs,
			fmt.Errorf("error while restoring backends: %w", err))
	}

	// Remove LB source ranges for no longer existing services
	if option.Config.EnableSVCSourceRangeCheck {
		if err := s.restoreAndDeleteOrphanSourceRanges(); err != nil {
			return err
		}
	}

	return errs
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

func (s *Service) restoreAndDeleteOrphanSourceRanges() error {
	opts := []bool{}
	if option.Config.EnableIPv4 {
		opts = append(opts, false)
	}
	if option.Config.EnableIPv6 {
		opts = append(opts, true)
	}

	for _, ipv6 := range opts {
		srcRangesBySvcID, err := s.lbmap.DumpSourceRanges(ipv6)
		if err != nil {
			return err
		}
		for svcID, srcRanges := range srcRangesBySvcID {
			svc, found := s.svcByID[lb.ID(svcID)]
			if !found {
				// Delete ranges
				if err := s.lbmap.UpdateSourceRanges(svcID, srcRanges, nil, ipv6); err != nil {
					return err
				}
			} else {
				svc.loadBalancerSourceRanges = srcRanges
			}
		}
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

func (s *Service) createSVCInfoIfNotExist(p *lb.SVC) (*svcInfo, bool, bool,
	[]*cidr.CIDR, error) {

	prevSessionAffinity := false
	prevLoadBalancerSourceRanges := []*cidr.CIDR{}

	hash := p.Frontend.Hash()
	svc, found := s.svcByHash[hash]
	if !found {
		// Allocate service ID for the new service
		addrID, err := AcquireID(p.Frontend.L3n4Addr, uint32(p.Frontend.ID))
		if err != nil {
			return nil, false, false, nil,
				fmt.Errorf("Unable to allocate service ID %d for %v: %s",
					p.Frontend.ID, p.Frontend, err)
		}
		p.Frontend.ID = addrID.ID

		svc = &svcInfo{
			hash:          hash,
			frontend:      p.Frontend,
			backendByHash: map[string]*lb.Backend{},

			svcType:      p.Type,
			svcName:      p.Name,
			svcNamespace: p.Namespace,

			sessionAffinity:           p.SessionAffinity,
			sessionAffinityTimeoutSec: p.SessionAffinityTimeoutSec,

			svcTrafficPolicy:         p.TrafficPolicy,
			svcHealthCheckNodePort:   p.HealthCheckNodePort,
			loadBalancerSourceRanges: p.LoadBalancerSourceRanges,
		}
		s.svcByID[p.Frontend.ID] = svc
		s.svcByHash[hash] = svc
	} else {
		// Local Redirect Policies with service matcher would have same frontend
		// as the service clusterIP type. In such cases, if a Local redirect service
		// exists, we shouldn't override it with clusterIP type (e.g., k8s event/sync, etc).
		if svc.svcType == lb.SVCTypeLocalRedirect && p.Type == lb.SVCTypeClusterIP {
			err := fmt.Errorf("local-redirect service exists for "+
				"frontend %v, skip update for svc %v", p.Frontend, p.Name)
			return svc, !found, prevSessionAffinity, prevLoadBalancerSourceRanges, err

		}
		// Local-redirect service can only override clusterIP service type or itself.
		if p.Type == lb.SVCTypeLocalRedirect &&
			(svc.svcType != lb.SVCTypeClusterIP && svc.svcType != lb.SVCTypeLocalRedirect) {
			err := fmt.Errorf("skip local-redirect service for "+
				"frontend %v as it overlaps with svc %v of type %v",
				p.Frontend, svc.svcName, svc.svcType)
			return svc, !found, prevSessionAffinity, prevLoadBalancerSourceRanges, err
		}
		prevSessionAffinity = svc.sessionAffinity
		prevLoadBalancerSourceRanges = svc.loadBalancerSourceRanges
		svc.svcType = p.Type
		svc.svcTrafficPolicy = p.TrafficPolicy
		svc.svcHealthCheckNodePort = p.HealthCheckNodePort
		svc.sessionAffinity = p.SessionAffinity
		svc.sessionAffinityTimeoutSec = p.SessionAffinityTimeoutSec
		svc.loadBalancerSourceRanges = p.LoadBalancerSourceRanges
		// Name and namespace are both optional and intended for exposure via
		// API. They they are not part of any BPF maps and cannot be restored
		// from datapath.
		if p.Name != "" {
			svc.svcName = p.Name
		}
		if p.Namespace != "" {
			svc.svcNamespace = p.Namespace
		}
		// We have heard about the service from k8s, so unset the flag so that
		// SyncWithK8sFinished() won't consider the service obsolete, and thus
		// won't remove it.
		svc.restoredFromDatapath = false
	}

	return svc, !found, prevSessionAffinity, prevLoadBalancerSourceRanges, nil
}

func (s *Service) deleteBackendsFromAffinityMatchMap(svcID lb.ID, backendIDs []lb.BackendID) {
	log.WithFields(logrus.Fields{
		logfields.Backends:  backendIDs,
		logfields.ServiceID: svcID,
	}).Debug("Deleting backends from session affinity match")

	for _, bID := range backendIDs {
		if err := s.lbmap.DeleteAffinityMatch(uint16(svcID), bID); err != nil {
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
		if err := s.lbmap.AddAffinityMatch(uint16(svcID), bID); err != nil {
			log.WithFields(logrus.Fields{
				logfields.BackendID: bID,
				logfields.ServiceID: svcID,
			}).WithError(err).Warn("Unable to add entry to affinity match map")
		}
	}
}

func (s *Service) upsertServiceIntoLBMaps(svc *svcInfo, onlyLocalBackends bool,
	prevActiveBackendCount int, newBackends []lb.Backend, obsoleteBackendIDs []lb.BackendID,
	prevSessionAffinity bool, prevLoadBalancerSourceRanges []*cidr.CIDR,
	obsoleteSVCBackendIDs []lb.BackendID, scopedLog *logrus.Entry) error {

	ipv6 := svc.frontend.IsIPv6()

	var (
		toDeleteAffinity, toAddAffinity []lb.BackendID
		checkLBSrcRange                 bool
	)

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

	// Update LB source range check cidrs
	if option.Config.EnableSVCSourceRangeCheck {
		checkLBSrcRange = len(svc.loadBalancerSourceRanges) != 0
		if checkLBSrcRange || len(prevLoadBalancerSourceRanges) != 0 {
			if err := s.lbmap.UpdateSourceRanges(uint16(svc.frontend.ID),
				prevLoadBalancerSourceRanges, svc.loadBalancerSourceRanges,
				ipv6); err != nil {

				return err
			}
		}
	}

	// Add new backends into BPF maps
	for _, b := range newBackends {
		scopedLog.WithFields(logrus.Fields{
			logfields.BackendID: b.ID,
			logfields.L3n4Addr:  b.L3n4Addr,
		}).Debug("Adding new backend")

		if err := s.lbmap.AddBackend(b.ID, b.L3n4Addr.IP,
			b.L3n4Addr.L4Addr.Port, ipv6); err != nil {
			return err
		}
	}

	// Upsert service entries into BPF maps
	backends := make(map[string]lb.BackendID, len(svc.backends))
	activeBackendsCount := 0
	for _, b := range svc.backends {
		// Skip adding the terminating backend to the service map so that it
		// won't be selected to serve new requests. However, the backend is still
		// kept in the affinity and backend maps so that existing connections
		// are able to terminate gracefully. The final clean-up for the backend
		// will happen once the agent receives a delete event for the service
		// endpoint as it'll be part of obsoleteBackendIDs/obsoleteSVCBackendIDs
		// list passed to this function.
		if !b.Terminating {
			backends[b.String()] = b.ID
			activeBackendsCount++
		}
	}
	svc.activeBackendsCount = activeBackendsCount

	p := &lbmap.UpsertServiceParams{
		ID:                        uint16(svc.frontend.ID),
		IP:                        svc.frontend.L3n4Addr.IP,
		Port:                      svc.frontend.L3n4Addr.L4Addr.Port,
		Backends:                  backends,
		PrevActiveBackendCount:    prevActiveBackendCount,
		IPv6:                      ipv6,
		Type:                      svc.svcType,
		Local:                     onlyLocalBackends,
		Scope:                     svc.frontend.L3n4Addr.Scope,
		SessionAffinity:           svc.sessionAffinity,
		SessionAffinityTimeoutSec: svc.sessionAffinityTimeoutSec,
		CheckSourceRange:          checkLBSrcRange,
		UseMaglev:                 svc.useMaglev(),
	}
	if err := s.lbmap.UpsertService(p); err != nil {
		return err
	}

	if option.Config.EnableSessionAffinity {
		s.addBackendsToAffinityMatchMap(svc.frontend.ID, toAddAffinity)
	}

	// Remove backends not used by any service from BPF maps
	for _, id := range obsoleteBackendIDs {
		scopedLog.WithField(logfields.BackendID, id).
			Debug("Removing obsolete backend")

		if err := s.lbmap.DeleteBackendByID(id, ipv6); err != nil {
			log.WithError(err).WithField(logfields.BackendID, id).
				Warn("Failed to remove backend from maps")
		}
	}

	return nil
}

func (s *Service) restoreBackendsLocked(svcBackendsById map[lb.BackendID]struct{}) error {
	failed, restored, skipped := 0, 0, 0
	backends, err := s.lbmap.DumpBackendMaps()
	if err != nil {
		return fmt.Errorf("Unable to dump backend maps: %s", err)
	}

	for _, b := range backends {
		log.WithFields(logrus.Fields{
			logfields.BackendID: b.ID,
			logfields.L3n4Addr:  b.L3n4Addr.String(),
		}).Debug("Restoring backend")
		if _, ok := svcBackendsById[b.ID]; !ok && s.backendRefCount[b.L3n4Addr.Hash()] != 0 {
			// If a backend by id isn't referenced by any of the service entries,
			// it's likely to be a duplicate backend. This can happen when agent
			// leaked backend entries in the backends map prior to restart, and created
			// duplicate with different IDs but same L3n4Addr (hash).
			// As none of the service entries have a reference to these backends
			// in the services map, the duplicate backends were not available for
			// load-balancing new traffic. While there is a slim chance that the
			// duplicate backends could have previously established active connections,
			// and these connections can get disrupted. However, the leaks likely
			// happened when service entries were deleted, so those connections
			// were also expected to be terminated.
			// Regardless, delete the duplicates as this can affect restoration of current
			// active backends, and may prevent new backends getting added as map
			// size is limited, which can result in connectivity issues.
			id := b.ID
			DeleteBackendID(id)
			if err := s.lbmap.DeleteBackendByID(id, b.L3n4Addr.IsIPv6()); err != nil {
				log.Errorf("unable to delete duplicate backend: %v", id)
			}
			log.WithFields(logrus.Fields{
				logfields.BackendID: b.ID,
				logfields.L3n4Addr:  b.L3n4Addr,
			}).Debug("Duplicate backend entry not restored")
			skipped++
			continue
		}
		if err := RestoreBackendID(b.L3n4Addr, b.ID); err != nil {
			log.WithError(err).WithFields(logrus.Fields{
				logfields.BackendID: b.ID,
				logfields.L3n4Addr:  b.L3n4Addr,
			}).Warning("Unable to restore backend")
			failed++
			continue
		}
		restored++
		hash := b.L3n4Addr.Hash()
		s.backendByHash[hash] = b
	}

	log.WithFields(logrus.Fields{
		logfields.RestoredBackends: restored,
		logfields.FailedBackends:   failed,
		logfields.SkippedBackends:  skipped,
	}).Info("Restored backends from maps")

	return nil
}

func (s *Service) deleteOrphanBackends() error {
	for hash, b := range s.backendByHash {
		if s.backendRefCount[hash] == 0 {
			log.WithField(logfields.BackendID, b.ID).
				Debug("Removing orphan backend")

			DeleteBackendID(b.ID)
			if err := s.lbmap.DeleteBackendByID(b.ID, b.L3n4Addr.IsIPv6()); err != nil {
				return fmt.Errorf("Unable to remove backend %d from map: %s", b.ID, err)
			}
			delete(s.backendByHash, hash)
		}
	}

	return nil
}

func (s *Service) restoreServicesLocked(svcBackendsById map[lb.BackendID]struct{}) error {
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
			hash:                svc.Frontend.Hash(),
			frontend:            svc.Frontend,
			backends:            svc.Backends,
			activeBackendsCount: len(svc.Backends),
			backendByHash:       map[string]*lb.Backend{},
			svcType:             svc.Type,
			svcTrafficPolicy:    svc.TrafficPolicy,

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
			svcBackendsById[backend.ID] = struct{}{}
		}

		// Recalculate Maglev lookup tables if the maps were removed due to
		// the changed M param.
		ipv6 := newSVC.frontend.IsIPv6()
		if option.Config.DatapathMode == datapathOpt.DatapathModeLBOnly &&
			newSVC.useMaglev() && s.lbmap.IsMaglevLookupTableRecreated(ipv6) {

			backends := make(map[string]lb.BackendID, len(newSVC.backends))
			for _, b := range newSVC.backends {
				backends[b.String()] = b.ID
			}
			if err := s.lbmap.UpsertMaglevLookupTable(uint16(newSVC.frontend.ID), backends, ipv6); err != nil {
				scopedLog.WithError(err).Warning("Unable to upsert into the Maglev BPF map.")
				continue
			}
		}

		s.svcByHash[newSVC.hash] = newSVC
		s.svcByID[newSVC.frontend.ID] = newSVC
		restored++
	}

	log.WithFields(logrus.Fields{
		logfields.RestoredSVCs: restored,
		logfields.FailedSVCs:   failed,
	}).Info("Restored services from maps")

	return nil
}

func (s *Service) deleteServiceLocked(svc *svcInfo) error {
	ipv6 := svc.frontend.L3n4Addr.IsIPv6()
	obsoleteBackendIDs := s.deleteBackendsFromCacheLocked(svc)

	scopedLog := log.WithFields(logrus.Fields{
		logfields.ServiceID: svc.frontend.ID,
		logfields.ServiceIP: svc.frontend.L3n4Addr,
		logfields.Backends:  svc.backends,
	})
	scopedLog.Debug("Deleting service")

	if err := s.lbmap.DeleteService(svc.frontend, svc.activeBackendsCount, svc.useMaglev()); err != nil {
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

	if option.Config.EnableSVCSourceRangeCheck &&
		svc.svcType == lb.SVCTypeLoadBalancer {
		if err := s.lbmap.UpdateSourceRanges(uint16(svc.frontend.ID),
			svc.loadBalancerSourceRanges, nil, ipv6); err != nil {
			return err
		}
	}

	delete(s.svcByHash, svc.hash)
	delete(s.svcByID, svc.frontend.ID)

	for _, id := range obsoleteBackendIDs {
		scopedLog.WithField(logfields.BackendID, id).
			Debug("Deleting obsolete backend")

		if err := s.lbmap.DeleteBackendByID(id, ipv6); err != nil {
			return err
		}
	}
	if err := DeleteID(uint32(svc.frontend.ID)); err != nil {
		return fmt.Errorf("Unable to release service ID %d: %s", svc.frontend.ID, err)
	}

	if option.Config.EnableHealthCheckNodePort {
		s.healthServer.DeleteService(lb.ID(svc.frontend.ID))
	}

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

	msg := monitorAPI.ServiceUpsertMessage(id, fe, be, string(svcType), string(svcTrafficPolicy), svcName, svcNamespace)
	s.monitorNotify.SendNotification(msg)
}

func (s *Service) notifyMonitorServiceDelete(id lb.ID) {
	if s.monitorNotify != nil {
		s.monitorNotify.SendNotification(monitorAPI.ServiceDeleteMessage(uint32(id)))
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

// isWildcardAddr returns true if given frontend is used for wildcard svc lookups
// (by bpf_sock).
func isWildcardAddr(frontend lb.L3n4AddrID) bool {
	if frontend.IsIPv6() {
		return net.IPv6zero.Equal(frontend.IP)
	}
	return net.IPv4zero.Equal(frontend.IP)
}
