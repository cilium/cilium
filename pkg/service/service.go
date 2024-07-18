// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package service

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync/atomic"

	"github.com/sirupsen/logrus"
	"k8s.io/apimachinery/pkg/util/sets"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/cidr"
	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/counter"
	datapathOpt "github.com/cilium/cilium/pkg/datapath/option"
	"github.com/cilium/cilium/pkg/datapath/sockets"
	datapathTypes "github.com/cilium/cilium/pkg/datapath/types"
	"github.com/cilium/cilium/pkg/k8s"
	lb "github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/maps/lbmap"
	"github.com/cilium/cilium/pkg/metrics"
	monitorAgent "github.com/cilium/cilium/pkg/monitor/agent"
	monitorAPI "github.com/cilium/cilium/pkg/monitor/api"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/node/addressing"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/service/healthserver"
	"github.com/cilium/cilium/pkg/time"
)

// ErrLocalRedirectServiceExists represents an error when a Local redirect
// service exists with the same Frontend.
type ErrLocalRedirectServiceExists struct {
	frontend lb.L3n4AddrID
	name     lb.ServiceName
}

// NewErrLocalRedirectServiceExists returns a new ErrLocalRedirectServiceExists
func NewErrLocalRedirectServiceExists(frontend lb.L3n4AddrID, name lb.ServiceName) error {
	return &ErrLocalRedirectServiceExists{
		frontend: frontend,
		name:     name,
	}
}

func (e ErrLocalRedirectServiceExists) Error() string {
	return fmt.Sprintf("local-redirect service exists for "+
		"frontend %v, skip update for svc %v", e.frontend, e.name)
}

func (e *ErrLocalRedirectServiceExists) Is(target error) bool {
	t, ok := target.(*ErrLocalRedirectServiceExists)
	if !ok {
		return false
	}
	return e.frontend.DeepEqual(&t.frontend) && e.name == t.name
}

// healthServer is used to manage HealthCheckNodePort listeners
type healthServer interface {
	UpsertService(svcID lb.ID, svcNS, svcName string, localEndpoints int, port uint16)
	DeleteService(svcID lb.ID)
}

type svcInfo struct {
	hash     string
	frontend lb.L3n4AddrID
	backends []*lb.Backend
	// Hashed `backends`; pointing to the same objects.
	backendByHash map[string]*lb.Backend

	svcType                   lb.SVCType
	svcExtTrafficPolicy       lb.SVCTrafficPolicy
	svcIntTrafficPolicy       lb.SVCTrafficPolicy
	svcNatPolicy              lb.SVCNatPolicy
	sessionAffinity           bool
	sessionAffinityTimeoutSec uint32
	svcHealthCheckNodePort    uint16
	healthcheckFrontendHash   string
	svcName                   lb.ServiceName
	loadBalancerSourceRanges  []*cidr.CIDR
	l7LBProxyPort             uint16 // Non-zero for egress L7 LB services
	LoopbackHostport          bool

	restoredFromDatapath bool
	// The hashes of the backends restored from the datapath and
	// not yet heard about from the service cache.
	restoredBackendHashes sets.Set[string]
}

func (svc *svcInfo) isL7LBService() bool {
	return svc.l7LBProxyPort != 0
}

func (svc *svcInfo) deepCopyToLBSVC() *lb.SVC {
	backends := make([]*lb.Backend, len(svc.backends))
	for i, backend := range svc.backends {
		backends[i] = backend.DeepCopy()
	}
	return &lb.SVC{
		Frontend:            *svc.frontend.DeepCopy(),
		Backends:            backends,
		Type:                svc.svcType,
		ExtTrafficPolicy:    svc.svcExtTrafficPolicy,
		IntTrafficPolicy:    svc.svcIntTrafficPolicy,
		NatPolicy:           svc.svcNatPolicy,
		HealthCheckNodePort: svc.svcHealthCheckNodePort,
		Name:                svc.svcName,
		L7LBProxyPort:       svc.l7LBProxyPort,
		LoopbackHostport:    svc.LoopbackHostport,
	}
}

func (svc *svcInfo) isExtLocal() bool {
	switch svc.svcType {
	case lb.SVCTypeNodePort, lb.SVCTypeLoadBalancer, lb.SVCTypeExternalIPs:
		return svc.svcExtTrafficPolicy == lb.SVCTrafficPolicyLocal
	default:
		return false
	}
}

func (svc *svcInfo) isIntLocal() bool {
	switch svc.svcType {
	case lb.SVCTypeClusterIP, lb.SVCTypeNodePort, lb.SVCTypeLoadBalancer, lb.SVCTypeExternalIPs:
		return svc.svcIntTrafficPolicy == lb.SVCTrafficPolicyLocal
	default:
		return false
	}
}

func (svc *svcInfo) filterBackends(frontend lb.L3n4AddrID) bool {
	switch svc.svcType {
	case lb.SVCTypeLocalRedirect:
		return true
	default:
		// When both traffic policies are Local, there is only the external scope, which
		// should contain node-local backends only. Checking isExtLocal is still enough.
		switch frontend.Scope {
		case lb.ScopeExternal:
			if svc.svcType == lb.SVCTypeClusterIP {
				// ClusterIP doesn't support externalTrafficPolicy and has only the
				// external scope, which contains only node-local backends when
				// internalTrafficPolicy=Local.
				return svc.isIntLocal()
			}
			return svc.isExtLocal()
		case lb.ScopeInternal:
			return svc.isIntLocal()
		default:
			return false
		}
	}
}

func (svc *svcInfo) useMaglev() bool {
	if option.Config.NodePortAlg != option.NodePortAlgMaglev {
		return false
	}
	// Provision the Maglev LUT for ClusterIP only if ExternalClusterIP is
	// enabled because ClusterIP can also be accessed from outside with this
	// setting. We don't do it unconditionally to avoid increasing memory
	// footprint.
	if svc.svcType == lb.SVCTypeClusterIP && !option.Config.ExternalClusterIP {
		return false
	}
	// Wildcarded frontend is not exposed for external traffic.
	if svc.svcType == lb.SVCTypeNodePort && isWildcardAddr(svc.frontend) {
		return false
	}
	// Only provision the Maglev LUT for service types which are reachable
	// from outside the node.
	switch svc.svcType {
	case lb.SVCTypeClusterIP,
		lb.SVCTypeNodePort,
		lb.SVCTypeLoadBalancer,
		lb.SVCTypeHostPort,
		lb.SVCTypeExternalIPs:
		return true
	}
	return false
}

type L7LBInfo struct {
	// Backend Sync registrations that are interested in Service backend changes
	// to reflect this in a L7 loadbalancer (e.g. Envoy)
	backendSyncRegistrations map[BackendSyncer]struct{}

	// Name of the L7 LB resource (e.g. CEC) that needs this service to be redirected to an
	// L7 Loadbalancer specified in that resource.
	// Only one resource may do this for any given service.
	ownerRef L7LBResourceName

	// port number for L7 LB redirection. Can be zero if only backend sync
	// has been requested.
	proxyPort uint16

	// (sub)set of service's frontend ports to be redirected. If empty, all frontend ports will be redirected.
	ports []uint16
}

// isProtoAndPortMatch returns true if frontend has protocol TCP and its Port is in i.ports, or if
// i.ports is empty.
// 'ports' is typically short for no point optimizing the search.
func (i *L7LBInfo) isProtoAndPortMatch(fe *lb.L4Addr) bool {
	// L7 LB redirect is only supported for TCP frontends
	if fe.Protocol != lb.TCP {
		return false
	}

	// Empty 'ports' matches all ports
	if len(i.ports) == 0 {
		return true
	}

	for _, p := range i.ports {
		if p == fe.Port {
			return true
		}
	}
	return false
}

type L7LBResourceName struct {
	Namespace string
	Name      string
}

func (svc *svcInfo) checkLBSourceRange() bool {
	if option.Config.EnableSVCSourceRangeCheck {
		return len(svc.loadBalancerSourceRanges) != 0
	}

	return false
}

// Service is a service handler. Its main responsibility is to reflect
// service-related changes into BPF maps used by datapath BPF programs.
// The changes can be triggered either by k8s_watcher or directly by
// API calls to the /services endpoint.
type Service struct {
	lock.RWMutex

	svcByHash map[string]*svcInfo
	svcByID   map[lb.ID]*svcInfo

	backendRefCount counter.Counter[string]
	// only used to keep track of the existing hash->ID mapping,
	// not for loadbalancing decisions.
	backendByHash map[string]*lb.Backend

	healthServer healthServer
	monitorAgent monitorAgent.Agent

	lbmap         datapathTypes.LBMap
	lastUpdatedTs atomic.Value

	l7lbSvcs map[lb.ServiceName]*L7LBInfo

	backendConnectionHandler sockets.SocketDestroyer

	backendDiscovery datapathTypes.NodeNeighbors
}

// newService creates a new instance of the service handler.
func newService(monitorAgent monitorAgent.Agent, lbmap datapathTypes.LBMap, backendDiscoveryHandler datapathTypes.NodeNeighbors) *Service {
	var localHealthServer healthServer
	if option.Config.EnableHealthCheckNodePort {
		localHealthServer = healthserver.New()
	}

	svc := &Service{
		svcByHash:                map[string]*svcInfo{},
		svcByID:                  map[lb.ID]*svcInfo{},
		backendRefCount:          counter.Counter[string]{},
		backendByHash:            map[string]*lb.Backend{},
		monitorAgent:             monitorAgent,
		healthServer:             localHealthServer,
		lbmap:                    lbmap,
		l7lbSvcs:                 map[lb.ServiceName]*L7LBInfo{},
		backendConnectionHandler: backendConnectionHandler{},
		backendDiscovery:         backendDiscoveryHandler,
	}
	svc.lastUpdatedTs.Store(time.Now())

	return svc
}

// RegisterL7LBServiceRedirect makes the given service to be locally redirected to the
// given proxy port.
func (s *Service) RegisterL7LBServiceRedirect(serviceName lb.ServiceName, resourceName L7LBResourceName, proxyPort uint16, frontendPorts []uint16) error {
	if proxyPort == 0 {
		return errors.New("proxy port for L7 LB redirection must be nonzero")
	}

	if logging.CanLogAt(log.Logger, logrus.DebugLevel) {
		log.WithFields(logrus.Fields{
			logfields.ServiceName:       serviceName.Name,
			logfields.ServiceNamespace:  serviceName.Namespace,
			logfields.L7LBProxyPort:     proxyPort,
			logfields.L7LBFrontendPorts: frontendPorts,
		}).Debug("Registering service for L7 proxy port redirection")
	}

	s.Lock()
	defer s.Unlock()

	err := s.registerL7LBServiceRedirect(serviceName, resourceName, proxyPort, frontendPorts)
	if err != nil {
		return err
	}

	return s.reUpsertServicesByName(serviceName.Name, serviceName.Namespace)
}

// 's' must be locked
func (s *Service) registerL7LBServiceRedirect(serviceName lb.ServiceName, resourceName L7LBResourceName, proxyPort uint16, frontendPorts []uint16) error {
	info := s.l7lbSvcs[serviceName]
	if info == nil {
		info = &L7LBInfo{}
	}

	// Only one CEC resource for a given service may request L7 LB redirection at a time.
	empty := L7LBResourceName{}
	if info.ownerRef != empty && info.ownerRef != resourceName {
		return fmt.Errorf("Service %q already registered for L7 LB redirection via a proxy resource %q", serviceName, info.ownerRef)
	}

	info.ownerRef = resourceName
	info.proxyPort = proxyPort

	if len(frontendPorts) == 0 {
		info.ports = nil
	} else {
		info.ports = make([]uint16, len(frontendPorts))
		copy(info.ports, frontendPorts)
	}

	s.l7lbSvcs[serviceName] = info

	return nil
}

// RegisterL7LBServiceBackendSync registers a BackendSync to be informed when the backends of a Service change.
func (s *Service) RegisterL7LBServiceBackendSync(serviceName lb.ServiceName, backendSyncRegistration BackendSyncer) error {
	if backendSyncRegistration == nil {
		return nil
	}

	if logging.CanLogAt(log.Logger, logrus.DebugLevel) {
		log.WithFields(logrus.Fields{
			logfields.ServiceName:      serviceName.Name,
			logfields.ServiceNamespace: serviceName.Namespace,
			logfields.ProxyName:        backendSyncRegistration.ProxyName(),
		}).Debug("Registering service backend sync for L7 loadbalancer")
	}

	s.Lock()
	defer s.Unlock()
	s.registerL7LBServiceBackendSync(serviceName, backendSyncRegistration)

	return s.reUpsertServicesByName(serviceName.Name, serviceName.Namespace)
}

// 's' must be locked
func (s *Service) registerL7LBServiceBackendSync(serviceName lb.ServiceName, backendSyncRegistration BackendSyncer) {
	info := s.l7lbSvcs[serviceName]
	if info == nil {
		info = &L7LBInfo{}
	}

	if info.backendSyncRegistrations == nil {
		info.backendSyncRegistrations = make(map[BackendSyncer]struct{}, 1)
	}
	info.backendSyncRegistrations[backendSyncRegistration] = struct{}{}

	s.l7lbSvcs[serviceName] = info
}

func (s *Service) DeregisterL7LBServiceRedirect(serviceName lb.ServiceName, resourceName L7LBResourceName) error {
	if logging.CanLogAt(log.Logger, logrus.DebugLevel) {
		log.WithFields(logrus.Fields{
			logfields.ServiceName:      serviceName.Name,
			logfields.ServiceNamespace: serviceName.Namespace,
		}).Debug("Deregistering service from L7 load balancing")
	}

	s.Lock()
	defer s.Unlock()

	changed := s.deregisterL7LBServiceRedirect(serviceName, resourceName)

	if !changed {
		return nil
	}

	return s.reUpsertServicesByName(serviceName.Name, serviceName.Namespace)
}

func (s *Service) deregisterL7LBServiceRedirect(serviceName lb.ServiceName, resourceName L7LBResourceName) bool {
	info, found := s.l7lbSvcs[serviceName]
	if !found {
		return false
	}

	empty := L7LBResourceName{}

	changed := false

	if info.ownerRef == resourceName {
		info.ownerRef = empty
		info.proxyPort = 0
		changed = true
	}

	if len(info.backendSyncRegistrations) == 0 && info.ownerRef == empty {
		delete(s.l7lbSvcs, serviceName)
		changed = true
	}

	return changed
}

func (s *Service) DeregisterL7LBServiceBackendSync(serviceName lb.ServiceName, backendSyncRegistration BackendSyncer) error {
	if backendSyncRegistration == nil {
		return nil
	}

	if logging.CanLogAt(log.Logger, logrus.DebugLevel) {
		log.WithFields(logrus.Fields{
			logfields.ServiceName:      serviceName.Name,
			logfields.ServiceNamespace: serviceName.Namespace,
			logfields.ProxyName:        backendSyncRegistration.ProxyName(),
		}).Debug("Deregistering service backend sync for L7 loadbalancer")
	}

	s.Lock()
	defer s.Unlock()
	changed := s.deregisterL7LBServiceBackendSync(serviceName, backendSyncRegistration)

	if !changed {
		return nil
	}

	return s.reUpsertServicesByName(serviceName.Name, serviceName.Namespace)
}

func (s *Service) deregisterL7LBServiceBackendSync(serviceName lb.ServiceName, backendSyncRegistration BackendSyncer) bool {
	info, found := s.l7lbSvcs[serviceName]
	if !found {
		return false
	}

	if info.backendSyncRegistrations == nil {
		return false
	}

	if _, registered := info.backendSyncRegistrations[backendSyncRegistration]; !registered {
		return false
	}

	delete(info.backendSyncRegistrations, backendSyncRegistration)

	empty := L7LBResourceName{}
	if len(info.backendSyncRegistrations) == 0 && info.ownerRef == empty {
		delete(s.l7lbSvcs, serviceName)
	}

	return true
}

// BackendSyncer performs a synchronization of service backends to an
// external loadbalancer (e.g. Envoy L7 Loadbalancer).
type BackendSyncer interface {
	// ProxyName returns a human readable name of the L7 Proxy that acts as
	// // L7 loadbalancer.
	ProxyName() string

	// Sync triggers the actual synchronization and passes the information
	// about the service that should be synchronized.
	Sync(svc *lb.SVC) error
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

func (s *Service) populateBackendMapV3FromV2(ipv4, ipv6 bool) error {
	const (
		v4 = "ipv4"
		v6 = "ipv6"
	)

	enabled := map[string]bool{v4: ipv4, v6: ipv6}

	for v, e := range enabled {
		if !e {
			continue
		}

		var (
			err          error
			v2Map        *bpf.Map
			v3Map        *bpf.Map
			v3BackendVal lbmap.BackendValue
		)

		copyBackendEntries := func(key bpf.MapKey, value bpf.MapValue) {
			if v == v4 {
				v3Map = lbmap.Backend4MapV3
				v1BackendVal := value.(*lbmap.Backend4Value)
				addrCluster := cmtypes.AddrClusterFrom(v1BackendVal.Address.Addr(), 0)
				v3BackendVal, err = lbmap.NewBackend4ValueV3(
					addrCluster,
					v1BackendVal.Port,
					v1BackendVal.Proto,
					lb.GetBackendStateFromFlags(v1BackendVal.Flags),
					0,
				)
				if err != nil {
					log.WithError(err).WithField(logfields.BPFMapName, v3Map.Name()).Debug("Error creating map value")
					return
				}
			} else {
				v3Map = lbmap.Backend6MapV3
				v1BackendVal := value.(*lbmap.Backend6Value)
				addrCluster := cmtypes.AddrClusterFrom(v1BackendVal.Address.Addr(), 0)
				v3BackendVal, err = lbmap.NewBackend6ValueV3(
					addrCluster,
					v1BackendVal.Port,
					v1BackendVal.Proto,
					lb.GetBackendStateFromFlags(v1BackendVal.Flags),
					0,
				)
				if err != nil {
					log.WithError(err).WithField(logfields.BPFMapName, v3Map.Name()).Debug("Error creating map value")
					return
				}
			}

			err := v3Map.Update(key, v3BackendVal)
			if err != nil {
				log.WithError(err).WithField(logfields.BPFMapName, v3Map.Name()).Warn("Error updating map")
			}
		}

		if v == v4 {
			v2Map = lbmap.Backend4MapV2
		} else {
			v2Map = lbmap.Backend6MapV2
		}

		err = v2Map.DumpWithCallback(copyBackendEntries)
		if err != nil {
			return fmt.Errorf("unable to populate %s: %w", v2Map.Name(), err)
		}

		// V2 backend map will be removed from bpffs at this point,
		// the map will be actually removed once the last program
		// referencing it has been removed.
		err = v2Map.Close()
		if err != nil {
			log.WithError(err).WithField(logfields.BPFMapName, v2Map.Name()).Warn("Error closing map")
		}

		err = v2Map.Unpin()
		if err != nil {
			log.WithError(err).WithField(logfields.BPFMapName, v2Map.Name()).Warn("Error unpinning map")
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
		v2BackendMapExistsV4 bool
		v2BackendMapExistsV6 bool
	)

	toOpen := []*bpf.Map{}
	toDelete := []*bpf.Map{}
	if ipv6 {
		toOpen = append(toOpen, lbmap.Service6MapV2, lbmap.Backend6MapV3, lbmap.RevNat6Map)
		if !restore {
			toDelete = append(toDelete, lbmap.Service6MapV2, lbmap.Backend6MapV3, lbmap.RevNat6Map)
		}
		if sockMaps {
			if err := lbmap.CreateSockRevNat6Map(); err != nil {
				return err
			}
		}
		v2BackendMapExistsV6 = lbmap.Backend6MapV2.Open() == nil
	}
	if ipv4 {
		toOpen = append(toOpen, lbmap.Service4MapV2, lbmap.Backend4MapV3, lbmap.RevNat4Map)
		if !restore {
			toDelete = append(toDelete, lbmap.Service4MapV2, lbmap.Backend4MapV3, lbmap.RevNat4Map)
		}
		if sockMaps {
			if err := lbmap.CreateSockRevNat4Map(); err != nil {
				return err
			}
		}
		v2BackendMapExistsV4 = lbmap.Backend4MapV2.Open() == nil
	}

	for _, m := range toOpen {
		if err := m.OpenOrCreate(); err != nil {
			return err
		}
	}
	for _, m := range toDelete {
		if err := m.DeleteAll(); err != nil {
			return err
		}
	}

	if v2BackendMapExistsV4 || v2BackendMapExistsV6 {
		log.Info("Backend map v2 exists. Migrating entries to backend map v3.")
		if err := s.populateBackendMapV3FromV2(v2BackendMapExistsV4, v2BackendMapExistsV6); err != nil {
			log.WithError(err).Warn("Error populating V3 map from V2 map, might interrupt existing connections during upgrade")
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
	return s.upsertService(params)
}

// reUpsertServicesByName upserts a service again to update it's internal state after
// changes for L7 service redirection.
// Write lock on 's' must be held.
func (s *Service) reUpsertServicesByName(name, namespace string) error {
	for _, svc := range s.svcByHash {
		if svc.svcName.Name == name && svc.svcName.Namespace == namespace {
			svcCopy := svc.deepCopyToLBSVC()
			if _, _, err := s.upsertService(svcCopy); err != nil {
				return fmt.Errorf("error while updating service in LB map: %w", err)
			}
		}
	}
	return nil
}

func (s *Service) upsertService(params *lb.SVC) (bool, lb.ID, error) {
	empty := L7LBResourceName{}

	// Set L7 LB for this service if registered.
	l7lbInfo, exists := s.l7lbSvcs[params.Name]
	if exists && l7lbInfo.ownerRef != empty && l7lbInfo.isProtoAndPortMatch(&params.Frontend.L4Addr) {
		params.L7LBProxyPort = l7lbInfo.proxyPort
	} else {
		params.L7LBProxyPort = 0
	}

	// L7 LB is sharing a C union in the datapath, disable session
	// affinity if L7 LB is configured for this service.
	if params.L7LBProxyPort != 0 {
		params.SessionAffinity = false
		params.SessionAffinityTimeoutSec = 0
	}

	// Implement a "lazy load" function for the scoped logger, so the expensive
	// call to 'WithFields' is only done if needed.
	debugLogsEnabled := logging.CanLogAt(log.Logger, logrus.DebugLevel)
	scopedLog := log
	scopedLogPopulated := false
	getScopedLog := func() *logrus.Entry {
		if !scopedLogPopulated {
			scopedLog = scopedLog.WithFields(logrus.Fields{
				logfields.ServiceIP: params.Frontend.L3n4Addr,
				logfields.Backends:  params.Backends,

				logfields.ServiceType:                params.Type,
				logfields.ServiceExtTrafficPolicy:    params.ExtTrafficPolicy,
				logfields.ServiceIntTrafficPolicy:    params.IntTrafficPolicy,
				logfields.ServiceHealthCheckNodePort: params.HealthCheckNodePort,
				logfields.ServiceName:                params.Name.Name,
				logfields.ServiceNamespace:           params.Name.Namespace,

				logfields.SessionAffinity:        params.SessionAffinity,
				logfields.SessionAffinityTimeout: params.SessionAffinityTimeoutSec,

				logfields.LoadBalancerSourceRanges: params.LoadBalancerSourceRanges,

				logfields.L7LBProxyPort: params.L7LBProxyPort,
			})

			scopedLogPopulated = true
		}
		return scopedLog
	}

	if debugLogsEnabled {
		getScopedLog().Debug("Upserting service")
	}

	if !option.Config.EnableSVCSourceRangeCheck &&
		len(params.LoadBalancerSourceRanges) != 0 {
		getScopedLog().Warnf("--%s is disabled, ignoring loadBalancerSourceRanges",
			option.EnableSVCSourceRangeCheck)
	}

	// Backends must either be the same IP proto as the frontend, or can be of
	// a different proto for NAT46/64. However, backends must be consistently
	// either v4 or v6, but not a mix.
	v4Seen := 0
	v6Seen := 0
	for _, b := range params.Backends {
		if b.L3n4Addr.IsIPv6() {
			v6Seen++
		} else {
			v4Seen++
		}
	}
	if v4Seen > 0 && v6Seen > 0 {
		err := fmt.Errorf("Unable to upsert service %s with a mixed set of IPv4 and IPv6 backends", params.Frontend.L3n4Addr.String())
		return false, lb.ID(0), err
	}
	v6Svc := params.Frontend.IsIPv6()
	if (v6Svc || v6Seen > 0) && !option.Config.EnableIPv6 {
		err := fmt.Errorf("Unable to upsert service %s as IPv6 is disabled", params.Frontend.L3n4Addr.String())
		return false, lb.ID(0), err
	}
	if (!v6Svc || v4Seen > 0) && !option.Config.EnableIPv4 {
		err := fmt.Errorf("Unable to upsert service %s as IPv4 is disabled", params.Frontend.L3n4Addr.String())
		return false, lb.ID(0), err
	}
	params.NatPolicy = lb.SVCNatPolicyNone
	if v6Svc && v4Seen > 0 {
		params.NatPolicy = lb.SVCNatPolicyNat64
	} else if !v6Svc && v6Seen > 0 {
		params.NatPolicy = lb.SVCNatPolicyNat46
	}
	if params.NatPolicy != lb.SVCNatPolicyNone && !option.Config.NodePortNat46X64 {
		err := fmt.Errorf("Unable to upsert service %s as NAT46/64 is disabled", params.Frontend.L3n4Addr.String())
		return false, lb.ID(0), err
	}

	// If needed, create svcInfo and allocate service ID
	svc, new, prevSessionAffinity, prevLoadBalancerSourceRanges, err := s.createSVCInfoIfNotExist(params)
	if err != nil {
		return false, lb.ID(0), err
	}

	// TODO(brb) defer ServiceID release after we have a lbmap "rollback"
	// If getScopedLog() has not been called, this field will still be included
	// from this point on in the function.
	scopedLog = scopedLog.WithField(logfields.ServiceID, svc.frontend.ID)
	if debugLogsEnabled {
		getScopedLog().Debug("Acquired service ID")
	}

	filterBackends := svc.filterBackends(params.Frontend)
	prevBackendCount := len(svc.backends)

	backendsCopy := []*lb.Backend{}
	for _, b := range params.Backends {
		// Local redirect services or services with trafficPolicy=Local may
		// only use node-local backends for external scope. We implement this by
		// filtering out all backend IPs which are not a local endpoint.
		if filterBackends && len(b.NodeName) > 0 && b.NodeName != nodeTypes.GetName() {
			continue
		}
		backendsCopy = append(backendsCopy, b.DeepCopy())
	}

	// Update backends cache and allocate/release backend IDs
	newBackends, obsoleteBackends, obsoleteSVCBackendIDs, err := s.updateBackendsCacheLocked(svc, backendsCopy)
	if err != nil {
		return false, lb.ID(0), err
	}

	if l7lbInfo != nil {
		for bs := range l7lbInfo.backendSyncRegistrations {
			svcCopy := svc.deepCopyToLBSVC()
			if err := bs.Sync(svcCopy); err != nil {
				return false, lb.ID(0), fmt.Errorf("failed to sync L7 LB backends (proxy: %s): %w", bs.ProxyName(), err)
			}
		}
	}

	// Update lbmaps (BPF service maps)
	if err = s.upsertServiceIntoLBMaps(svc, svc.isExtLocal(), svc.isIntLocal(), prevBackendCount,
		newBackends, obsoleteBackends, prevSessionAffinity, prevLoadBalancerSourceRanges,
		obsoleteSVCBackendIDs, getScopedLog, debugLogsEnabled); err != nil {
		return false, lb.ID(0), err
	}

	// Update managed neighbor entries of the LB
	if option.Config.DatapathMode == datapathOpt.DatapathModeLBOnly {
		s.upsertBackendNeighbors(newBackends, obsoleteBackends)
	}

	// Only add a HealthCheckNodePort server if this is a service which may
	// only contain local backends (i.e. it has externalTrafficPolicy=Local)
	if option.Config.EnableHealthCheckNodePort {
		if svc.isExtLocal() && filterBackends && svc.svcHealthCheckNodePort > 0 {
			// HealthCheckNodePort is used by external systems to poll the state of the Service,
			// it should never take into consideration Terminating backends, even when there are only
			// Terminating backends.
			//
			// There is one special case is L7 proxy service, which never have any
			// backends because the traffic will be redirected.
			activeBackends := 0
			if l7lbInfo != nil {
				// Set this to 1 because Envoy will be running in this case.
				getScopedLog().WithField(logfields.ServiceHealthCheckNodePort, svc.svcHealthCheckNodePort).
					Debug("L7 service with HealthcheckNodePort enabled")
				activeBackends = 1
			} else {
				for _, b := range backendsCopy {
					if b.State == lb.BackendStateActive {
						activeBackends++
					}
				}
			}
			s.healthServer.UpsertService(svc.frontend.ID, svc.svcName.Namespace, svc.svcName.Name,
				activeBackends, svc.svcHealthCheckNodePort)

			if err = s.upsertNodePortHealthService(svc, &nodeMetaCollector{}); err != nil {
				return false, lb.ID(0), fmt.Errorf("upserting NodePort health service failed: %w", err)
			}

		} else if svc.svcHealthCheckNodePort == 0 {
			// Remove the health check server in case this service used to have
			// externalTrafficPolicy=Local with HealthCheckNodePort in the previous
			// version, but not anymore.
			s.healthServer.DeleteService(lb.ID(svc.frontend.ID))

			if svc.healthcheckFrontendHash != "" {
				healthSvc := s.svcByHash[svc.healthcheckFrontendHash]
				if healthSvc != nil {
					s.deleteServiceLocked(healthSvc)
				}
				svc.healthcheckFrontendHash = ""
			}
		}
	}

	if new {
		metrics.ServicesEventsCount.WithLabelValues("add").Inc()
	} else {
		metrics.ServicesEventsCount.WithLabelValues("update").Inc()
	}

	s.notifyMonitorServiceUpsert(svc.frontend, svc.backends,
		svc.svcType, svc.svcExtTrafficPolicy, svc.svcIntTrafficPolicy, svc.svcName.Name, svc.svcName.Namespace)
	return new, lb.ID(svc.frontend.ID), nil
}

type NodeMetaCollector interface {
	GetIPv4() net.IP
	GetIPv6() net.IP
}

type nodeMetaCollector struct{}

func (n *nodeMetaCollector) GetIPv4() net.IP {
	return node.GetIPv4()
}

func (n *nodeMetaCollector) GetIPv6() net.IP {
	return node.GetIPv6()
}

// upsertNodePortHealthService makes the HealthCheckNodePort available to the external IP of the service
func (s *Service) upsertNodePortHealthService(svc *svcInfo, nodeMeta NodeMetaCollector) error {
	// For any service that has a healthCheckNodePort, we create a healthCheck service
	// The service that is created does not need an another healthCheck service.
	// The easiest way end that loop is to check for the HealthCheckNodePort
	// Also, without a healthCheckNodePort, we don't need to create a healthCheck service
	if !option.Config.EnableHealthCheckLoadBalancerIP || svc.svcType != lb.SVCTypeLoadBalancer || svc.svcHealthCheckNodePort == 0 {
		if svc.healthcheckFrontendHash == "" {
			return nil
		}

		healthSvc := s.svcByHash[svc.healthcheckFrontendHash]
		if healthSvc != nil {
			s.deleteServiceLocked(healthSvc)
		}
		svc.healthcheckFrontendHash = ""

		return nil
	}

	healthCheckSvcName := svc.svcName
	healthCheckSvcName.Name = svc.svcName.Name + "-healthCheck"

	healthCheckFrontend := *lb.NewL3n4AddrID(
		lb.TCP,
		svc.frontend.AddrCluster,
		svc.svcHealthCheckNodePort,
		lb.ScopeExternal,
		0,
	)

	if svc.healthcheckFrontendHash != "" && svc.healthcheckFrontendHash != healthCheckFrontend.Hash() {
		healthSvc := s.svcByHash[svc.healthcheckFrontendHash]
		if healthSvc != nil {
			s.deleteServiceLocked(healthSvc)
		}
	}

	var ip netip.Addr
	var ok bool
	if svc.frontend.AddrCluster.Is4() {
		ip, ok = netip.AddrFromSlice(nodeMeta.GetIPv4().To4())
	} else {
		ip, ok = netip.AddrFromSlice(nodeMeta.GetIPv6())
	}

	if !ok {
		return fmt.Errorf("failed to parse node IP")
	}

	clusterAddr := cmtypes.AddrClusterFrom(ip, option.Config.ClusterID)

	healthCheckBackends := []*lb.Backend{
		{
			L3n4Addr: *lb.NewL3n4Addr(lb.TCP, clusterAddr, svc.svcHealthCheckNodePort, lb.ScopeInternal),
			State:    lb.BackendStateActive,
			NodeName: nodeTypes.GetName(),
		},
	}
	// Create a new service with the healthcheck frontend and healthcheck backend
	healthCheckSvc := &lb.SVC{
		Name:             healthCheckSvcName,
		Type:             svc.svcType,
		Frontend:         healthCheckFrontend,
		ExtTrafficPolicy: lb.SVCTrafficPolicyLocal,
		IntTrafficPolicy: lb.SVCTrafficPolicyLocal,
		Backends:         healthCheckBackends,
		LoopbackHostport: true,
	}

	_, _, err := s.upsertService(healthCheckSvc)
	if err != nil {
		return err
	}
	svc.healthcheckFrontendHash = healthCheckFrontend.Hash()

	log.WithFields(logrus.Fields{
		logfields.ServiceName:      svc.svcName.Name,
		logfields.ServiceNamespace: svc.svcName.Namespace,
	}).Debug("Created healthcheck service for frontend")

	return nil
}

// UpdateBackendsState updates all the service(s) with the updated state of
// the given backends. It also persists the updated backend states to the BPF maps.
//
// Backend state transitions are validated before processing.
//
// In case of duplicated backends in the list, the state will be updated to the
// last duplicate entry.
func (s *Service) UpdateBackendsState(backends []*lb.Backend) error {
	if len(backends) == 0 {
		return nil
	}

	if logging.CanLogAt(log.Logger, logrus.DebugLevel) {
		for _, b := range backends {
			log.WithFields(logrus.Fields{
				logfields.L3n4Addr:         b.L3n4Addr.String(),
				logfields.BackendState:     b.State,
				logfields.BackendPreferred: b.Preferred,
			}).Debug("Update backend states")
		}
	}

	var (
		errs            error
		updatedBackends []*lb.Backend
	)
	updateSvcs := make(map[lb.ID]*datapathTypes.UpsertServiceParams)

	s.Lock()
	defer s.Unlock()
	for _, updatedB := range backends {
		hash := updatedB.L3n4Addr.Hash()

		be, exists := s.backendByHash[hash]
		if !exists {
			// Cilium service API and Kubernetes events are asynchronous, so it's
			// possible to receive an API call for a backend that's already deleted.
			continue
		}
		if !lb.IsValidStateTransition(be.State, updatedB.State) {
			currentState, _ := be.State.String()
			newState, _ := updatedB.State.String()
			errs = errors.Join(errs,
				fmt.Errorf("invalid state transition for backend[%s] (%s) -> (%s)",
					updatedB.String(), currentState, newState),
			)
			continue
		}
		be.State = updatedB.State
		be.Preferred = updatedB.Preferred

		for id, info := range s.svcByID {
			var p *datapathTypes.UpsertServiceParams
			for i, b := range info.backends {
				if b.L3n4Addr.String() != updatedB.L3n4Addr.String() {
					continue
				}
				if b.State == updatedB.State {
					break
				}
				info.backends[i].State = updatedB.State
				info.backends[i].Preferred = updatedB.Preferred
				found := false

				if p, found = updateSvcs[id]; !found {
					p = &datapathTypes.UpsertServiceParams{
						ID:                        uint16(id),
						IP:                        info.frontend.L3n4Addr.AddrCluster.AsNetIP(),
						Port:                      info.frontend.L3n4Addr.L4Addr.Port,
						PrevBackendsCount:         len(info.backends),
						IPv6:                      info.frontend.IsIPv6(),
						Type:                      info.svcType,
						ExtLocal:                  info.isExtLocal(),
						IntLocal:                  info.isIntLocal(),
						Scope:                     info.frontend.L3n4Addr.Scope,
						SessionAffinity:           info.sessionAffinity,
						SessionAffinityTimeoutSec: info.sessionAffinityTimeoutSec,
						CheckSourceRange:          info.checkLBSourceRange(),
						UseMaglev:                 info.useMaglev(),
						Name:                      info.svcName,
						LoopbackHostport:          info.LoopbackHostport,
					}
				}
				p.PreferredBackends, p.ActiveBackends, p.NonActiveBackends = segregateBackends(info.backends)
				updateSvcs[id] = p
				log.WithFields(logrus.Fields{
					logfields.ServiceID:        p.ID,
					logfields.BackendID:        b.ID,
					logfields.L3n4Addr:         b.L3n4Addr.String(),
					logfields.BackendState:     b.State,
					logfields.BackendPreferred: b.Preferred,
				}).Info("Persisting service with backend state update")
			}
			s.svcByID[id] = info
			s.svcByHash[info.frontend.Hash()] = info
		}
		updatedBackends = append(updatedBackends, be)
	}

	// Update the persisted backend state in BPF maps.
	for _, b := range updatedBackends {
		log.WithFields(logrus.Fields{
			logfields.BackendID:        b.ID,
			logfields.L3n4Addr:         b.L3n4Addr.String(),
			logfields.BackendState:     b.State,
			logfields.BackendPreferred: b.Preferred,
		}).Info("Persisting updated backend state for backend")
		if err := s.lbmap.UpdateBackendWithState(b); err != nil {
			errs = errors.Join(errs, fmt.Errorf("failed to update backend %+v: %w", b, err))
		}
	}

	for i := range updateSvcs {
		errs = errors.Join(errs, s.lbmap.UpsertService(updateSvcs[i]))
	}
	return errs
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

// GetDeepCopyServiceByFrontend returns a deep-copy of the service that matches the Frontend address.
func (s *Service) GetDeepCopyServiceByFrontend(frontend lb.L3n4Addr) (*lb.SVC, bool) {
	s.RLock()
	defer s.RUnlock()

	if svc, found := s.svcByHash[frontend.Hash()]; found {
		return svc.deepCopyToLBSVC(), true
	}

	return nil, false
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
	backendsById := make(map[lb.BackendID]struct{})

	var errs error
	// Restore service cache from BPF maps
	if err := s.restoreServicesLocked(backendsById); err != nil {
		errs = errors.Join(errs, fmt.Errorf("error while restoring services: %w", err))
	}

	// Restore backend IDs
	if err := s.restoreBackendsLocked(backendsById); err != nil {
		errs = errors.Join(errs, fmt.Errorf("error while restoring backends: %w", err))
	}

	// Remove LB source ranges for no longer existing services
	if option.Config.EnableSVCSourceRangeCheck {
		errs = errors.Join(errs, s.restoreAndDeleteOrphanSourceRanges())
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
//
// Additionally, it returns a list of services which are associated with
// stale backends, and which shall be refreshed. Stale services shall be
// refreshed regardless of whether an error is also returned or not.
//
// The localOnly flag allows to perform a two pass removal, handling local
// services first, and processing global ones only after full synchronization
// with all remote clusters.
func (s *Service) SyncWithK8sFinished(localOnly bool, localServices sets.Set[k8s.ServiceID]) (stale []k8s.ServiceID, err error) {
	s.Lock()
	defer s.Unlock()

	for _, svc := range s.svcByHash {
		svcID := k8s.ServiceID{
			Cluster:   svc.svcName.Cluster,
			Namespace: svc.svcName.Namespace,
			Name:      svc.svcName.Name,
		}

		// Skip processing global services when the localOnly flag is set.
		if localOnly && !localServices.Has(svcID) {
			continue
		}

		if svc.restoredFromDatapath {
			log.WithFields(logrus.Fields{
				logfields.ServiceID: svc.frontend.ID,
				logfields.L3n4Addr:  logfields.Repr(svc.frontend.L3n4Addr),
			}).
				Warn("Deleting no longer present service")

			if err := s.deleteServiceLocked(svc); err != nil {
				return stale, fmt.Errorf("Unable to remove service %+v: %w", svc, err)
			}
		} else if svc.restoredBackendHashes.Len() > 0 {
			// The service is still associated with stale backends
			stale = append(stale, svcID)
			log.WithFields(logrus.Fields{
				logfields.ServiceID:      svc.frontend.ID,
				logfields.ServiceName:    svc.svcName.String(),
				logfields.L3n4Addr:       logfields.Repr(svc.frontend.L3n4Addr),
				logfields.OrphanBackends: svc.restoredBackendHashes.Len(),
			}).Info("Service has stale backends: triggering refresh")
		}

		svc.restoredBackendHashes = nil
	}

	if localOnly {
		// Wait for full clustermesh synchronization before finalizing the
		// removal of orphan backends and affinity matches.
		return stale, nil
	}

	// Remove no longer existing affinity matches
	if option.Config.EnableSessionAffinity {
		if err := s.deleteOrphanAffinityMatchesLocked(); err != nil {
			return stale, err
		}
	}

	// Remove obsolete backends and release their IDs
	if err := s.deleteOrphanBackends(); err != nil {
		log.WithError(err).Warn("Failed to remove orphan backends")
	}

	return stale, nil
}

func (s *Service) createSVCInfoIfNotExist(p *lb.SVC) (*svcInfo, bool, bool,
	[]*cidr.CIDR, error,
) {
	prevSessionAffinity := false
	prevLoadBalancerSourceRanges := []*cidr.CIDR{}

	hash := p.Frontend.Hash()
	svc, found := s.svcByHash[hash]
	if !found {
		// Allocate service ID for the new service
		addrID, err := AcquireID(p.Frontend.L3n4Addr, uint32(p.Frontend.ID))
		if err != nil {
			return nil, false, false, nil,
				fmt.Errorf("Unable to allocate service ID %d for %v: %w",
					p.Frontend.ID, p.Frontend, err)
		}
		p.Frontend.ID = addrID.ID

		svc = &svcInfo{
			hash:          hash,
			frontend:      p.Frontend,
			backendByHash: map[string]*lb.Backend{},

			svcType: p.Type,
			svcName: p.Name,

			sessionAffinity:           p.SessionAffinity,
			sessionAffinityTimeoutSec: p.SessionAffinityTimeoutSec,

			svcExtTrafficPolicy:      p.ExtTrafficPolicy,
			svcIntTrafficPolicy:      p.IntTrafficPolicy,
			svcNatPolicy:             p.NatPolicy,
			svcHealthCheckNodePort:   p.HealthCheckNodePort,
			loadBalancerSourceRanges: p.LoadBalancerSourceRanges,
			l7LBProxyPort:            p.L7LBProxyPort,
			LoopbackHostport:         p.LoopbackHostport,
		}
		s.svcByID[p.Frontend.ID] = svc
		s.svcByHash[hash] = svc
	} else {
		// Local Redirect Policies with service matcher would have same frontend
		// as the service clusterIP type. In such cases, if a Local redirect service
		// exists, we shouldn't override it with clusterIP type (e.g., k8s event/sync, etc).
		if svc.svcType == lb.SVCTypeLocalRedirect && p.Type == lb.SVCTypeClusterIP {
			err := NewErrLocalRedirectServiceExists(p.Frontend, p.Name)
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
		svc.svcExtTrafficPolicy = p.ExtTrafficPolicy
		svc.svcIntTrafficPolicy = p.IntTrafficPolicy
		svc.svcNatPolicy = p.NatPolicy
		svc.svcHealthCheckNodePort = p.HealthCheckNodePort
		svc.sessionAffinity = p.SessionAffinity
		svc.sessionAffinityTimeoutSec = p.SessionAffinityTimeoutSec
		svc.loadBalancerSourceRanges = p.LoadBalancerSourceRanges
		// Name, namespace and cluster are optional and intended for exposure via
		// API. They they are not part of any BPF maps and cannot be restored
		// from datapath.
		if p.Name.Name != "" {
			svc.svcName.Name = p.Name.Name
		}
		if p.Name.Namespace != "" {
			svc.svcName.Namespace = p.Name.Namespace
		}
		if p.Name.Cluster != "" {
			svc.svcName.Cluster = p.Name.Cluster
		}
		// We have heard about the service from k8s, so unset the flag so that
		// SyncWithK8sFinished() won't consider the service obsolete, and thus
		// won't remove it.
		svc.restoredFromDatapath = false

		// Update L7 load balancer proxy port
		svc.l7LBProxyPort = p.L7LBProxyPort
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

func (s *Service) upsertServiceIntoLBMaps(svc *svcInfo, isExtLocal, isIntLocal bool,
	prevBackendCount int, newBackends []*lb.Backend, obsoleteBackends []*lb.Backend,
	prevSessionAffinity bool, prevLoadBalancerSourceRanges []*cidr.CIDR,
	obsoleteSVCBackendIDs []lb.BackendID, getScopedLog func() *logrus.Entry,
	debugLogsEnabled bool,
) error {
	v6FE := svc.frontend.IsIPv6()

	var (
		toDeleteAffinity, toAddAffinity []lb.BackendID
		checkLBSrcRange                 bool
	)

	// Update sessionAffinity
	//
	// If L7 LB is configured for this service then BPF level session affinity is not used so
	// that the L7 proxy port may be passed in a shared union in the service entry.
	if option.Config.EnableSessionAffinity && !svc.isL7LBService() {
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
				toDeleteAffinity = append(toDeleteAffinity, obsoleteSVCBackendIDs...)
			}
		}

		s.deleteBackendsFromAffinityMatchMap(svc.frontend.ID, toDeleteAffinity)
		// New affinity matches (toAddAffinity) will be added after the new
		// backends have been added.
	}

	// Update LB source range check cidrs
	if checkLBSrcRange = svc.checkLBSourceRange() || len(prevLoadBalancerSourceRanges) != 0; checkLBSrcRange {
		if err := s.lbmap.UpdateSourceRanges(uint16(svc.frontend.ID),
			prevLoadBalancerSourceRanges, svc.loadBalancerSourceRanges,
			v6FE); err != nil {
			return err
		}
	}

	// Add new backends into BPF maps
	for _, b := range newBackends {
		if debugLogsEnabled {
			getScopedLog().WithFields(logrus.Fields{
				logfields.BackendID:     b.ID,
				logfields.BackendWeight: b.Weight,
				logfields.L3n4Addr:      b.L3n4Addr,
			}).Debug("Adding new backend")
		}

		if err := s.lbmap.AddBackend(b, b.L3n4Addr.IsIPv6()); err != nil {
			return err
		}
	}

	// Upsert service entries into BPF maps
	preferredBackends, activeBackends, nonActiveBackends := segregateBackends(svc.backends)

	natPolicy := lb.SVCNatPolicyNone
	natPolicySet := false
	for _, b := range svc.backends {
		// All backends have been previously checked to be either v4 or v6.
		if !natPolicySet {
			natPolicySet = true
			v6BE := b.L3n4Addr.IsIPv6()
			if v6FE && !v6BE {
				natPolicy = lb.SVCNatPolicyNat64
			} else if !v6FE && v6BE {
				natPolicy = lb.SVCNatPolicyNat46
			}
		}
	}
	if natPolicy == lb.SVCNatPolicyNat64 {
		// Backends have been added to the v4 backend map, but we now also need
		// to add them to the v6 backend map as v4-in-v6 address. The reason is
		// that backends could be used by multiple services, so a v4->v4 service
		// expects them in the v4 map, but v6->v4 service enters the v6 datapath
		// and looks them up in the v6 backend map (v4-in-v6), and only later on
		// after DNAT transforms the packet into a v4 one.
		for _, b := range newBackends {
			if err := s.lbmap.AddBackend(b, true); err != nil {
				return err
			}
		}
	}
	svc.svcNatPolicy = natPolicy

	p := &datapathTypes.UpsertServiceParams{
		ID:                        uint16(svc.frontend.ID),
		IP:                        svc.frontend.L3n4Addr.AddrCluster.AsNetIP(),
		Port:                      svc.frontend.L3n4Addr.L4Addr.Port,
		PreferredBackends:         preferredBackends,
		ActiveBackends:            activeBackends,
		NonActiveBackends:         nonActiveBackends,
		PrevBackendsCount:         prevBackendCount,
		IPv6:                      v6FE,
		NatPolicy:                 natPolicy,
		Type:                      svc.svcType,
		ExtLocal:                  isExtLocal,
		IntLocal:                  isIntLocal,
		Scope:                     svc.frontend.L3n4Addr.Scope,
		SessionAffinity:           svc.sessionAffinity,
		SessionAffinityTimeoutSec: svc.sessionAffinityTimeoutSec,
		CheckSourceRange:          checkLBSrcRange,
		UseMaglev:                 svc.useMaglev(),
		L7LBProxyPort:             svc.l7LBProxyPort,
		Name:                      svc.svcName,
		LoopbackHostport:          svc.LoopbackHostport,
	}
	if err := s.lbmap.UpsertService(p); err != nil {
		return err
	}

	// If L7 LB is configured for this service then BPF level session affinity is not used.
	if option.Config.EnableSessionAffinity && !svc.isL7LBService() {
		s.addBackendsToAffinityMatchMap(svc.frontend.ID, toAddAffinity)
	}

	// Remove backends not used by any service from BPF maps
	for _, be := range obsoleteBackends {
		id := be.ID
		if debugLogsEnabled {
			getScopedLog().WithField(logfields.BackendID, id).
				Debug("Removing obsolete backend")
		}
		s.lbmap.DeleteBackendByID(id)
		s.TerminateUDPConnectionsToBackend(&be.L3n4Addr)
	}

	return nil
}

func (s *Service) restoreBackendsLocked(svcBackendsById map[lb.BackendID]struct{}) error {
	failed, restored, skipped := 0, 0, 0
	backends, err := s.lbmap.DumpBackendMaps()
	if err != nil {
		return fmt.Errorf("Unable to dump backend maps: %w", err)
	}

	debugLogsEnabled := logging.CanLogAt(log.Logger, logrus.DebugLevel)

	svcBackendsCount := len(svcBackendsById)
	for _, b := range backends {
		if debugLogsEnabled {
			log.WithFields(logrus.Fields{
				logfields.BackendID:        b.ID,
				logfields.L3n4Addr:         b.L3n4Addr.String(),
				logfields.BackendState:     b.State,
				logfields.BackendPreferred: b.Preferred,
			}).Debug("Restoring backend")
		}

		if _, ok := svcBackendsById[b.ID]; !ok && (svcBackendsCount != 0) {
			// If a backend by ID isn't referenced by any of the services, it's
			// likely a leaked backend. In case of duplicate leaked backends,
			// there would be multiple IDs allocated for the same backend resource
			// identified by its L3nL4Addr hash. The second check for service
			// backends count is added for unusual cases where there might've been
			// a problem with reading entries from the services map. In such cases,
			// the agent should not wipe out the backends map, as this can disrupt
			// existing connections. SyncWithK8sFinished will later sync the backends
			// map with the latest state.
			// Leaked backend scenarios:
			// 1) Backend entries leaked, no duplicates
			// 2) Backend entries leaked with duplicates:
			// 	a) backend with overlapping L3nL4Addr hash is associated with service(s)
			//     Sequence of events:
			//     Backends were leaked prior to agent restart, but there was at least
			//     one service that the backend by hash is associated with.
			//     s.backendByHash will have a non-zero reference count for the
			//     overlapping L3nL4Addr hash.
			// 	b) none of the backends are associated with services
			//     Sequence of events:
			// 	   All the services these backends were associated with were deleted
			//     prior to agent restart.
			//     s.backendByHash will not have an entry for the backends hash.
			// As none of the service entries have a reference to these backends
			// in the services map, the backends were likely not available for
			// load-balancing new traffic. While there is a slim chance that the
			// backends could have previously established active connections,
			// and these connections can get disrupted. However, the leaks likely
			// happened when service entries were deleted, so those connections
			// were also expected to be terminated.
			// Regardless, delete the duplicates as this can affect restoration of current
			// active backends, and may prevent new backends getting added as map
			// size is limited, which can lead to connectivity disruptions.
			id := b.ID
			DeleteBackendID(id)
			if err := s.lbmap.DeleteBackendByID(id); err != nil {
				// As the backends map is not expected to be updated during restore,
				// the deletion call shouldn't fail. But log the error, just
				// in case...
				log.Errorf("unable to delete leaked backend: %v", id)
			}
			if debugLogsEnabled {
				log.WithFields(logrus.Fields{
					logfields.BackendID:        b.ID,
					logfields.L3n4Addr:         b.L3n4Addr,
					logfields.BackendState:     b.State,
					logfields.BackendPreferred: b.Preferred,
				}).Debug("Leaked backend entry not restored")
			}
			skipped++
			continue
		}
		if err := RestoreBackendID(b.L3n4Addr, b.ID); err != nil {
			log.WithError(err).WithFields(logrus.Fields{
				logfields.BackendID:        b.ID,
				logfields.L3n4Addr:         b.L3n4Addr,
				logfields.BackendState:     b.State,
				logfields.BackendPreferred: b.Preferred,
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
	orphanBackends := 0

	for hash, b := range s.backendByHash {
		if s.backendRefCount[hash] == 0 {
			log.WithField(logfields.BackendID, b.ID).
				Debug("Removing orphan backend")
			// The b.ID is unique across IPv4/6, hence attempt
			// to clean it from both maps, and ignore errors.
			DeleteBackendID(b.ID)
			s.lbmap.DeleteBackendByID(b.ID)
			delete(s.backendByHash, hash)
			orphanBackends++
		}
	}
	log.WithFields(logrus.Fields{
		logfields.OrphanBackends: orphanBackends,
	}).Info("Deleted orphan backends")

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
			backendByHash:       map[string]*lb.Backend{},
			svcType:             svc.Type,
			svcExtTrafficPolicy: svc.ExtTrafficPolicy,
			svcIntTrafficPolicy: svc.IntTrafficPolicy,
			svcNatPolicy:        svc.NatPolicy,
			LoopbackHostport:    svc.LoopbackHostport,

			sessionAffinity:           svc.SessionAffinity,
			sessionAffinityTimeoutSec: svc.SessionAffinityTimeoutSec,

			// Indicate that the svc was restored from the BPF maps, so that
			// SyncWithK8sFinished() could remove services which were restored
			// from the maps but not present in the k8sServiceCache (e.g. a svc
			// was deleted while cilium-agent was down).
			restoredFromDatapath: true,
		}

		for j, backend := range svc.Backends {
			// DumpServiceMaps() can return services with some empty (nil) backends.
			if backend == nil {
				continue
			}

			hash := backend.L3n4Addr.Hash()
			s.backendRefCount.Add(hash)
			newSVC.backendByHash[hash] = svc.Backends[j]
			svcBackendsById[backend.ID] = struct{}{}
		}

		if len(newSVC.backendByHash) > 0 {
			// Indicate that these backends were restored from BPF maps,
			// so that they are not removed until SyncWithK8sFinished()
			// is executed (if not observed in the meanwhile) to prevent
			// disrupting valid connections.
			newSVC.restoredBackendHashes = sets.KeySet(newSVC.backendByHash)
		}

		// Recalculate Maglev lookup tables if the maps were removed due to
		// the changed M param.
		ipv6 := newSVC.frontend.IsIPv6() || (svc.NatPolicy == lb.SVCNatPolicyNat46)
		recreated := s.lbmap.IsMaglevLookupTableRecreated(ipv6)
		if option.Config.DatapathMode == datapathOpt.DatapathModeLBOnly &&
			newSVC.useMaglev() && recreated {

			backends := make(map[string]*lb.Backend, len(newSVC.backends))
			for _, b := range newSVC.backends {
				// DumpServiceMaps() can return services with some empty (nil) backends.
				if b == nil {
					continue
				}

				backends[b.String()] = b
			}
			if err := s.lbmap.UpsertMaglevLookupTable(uint16(newSVC.frontend.ID), backends,
				ipv6); err != nil {
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
	ipv6 := svc.frontend.L3n4Addr.IsIPv6() || svc.svcNatPolicy == lb.SVCNatPolicyNat46
	obsoleteBackendIDs, obsoleteBackends := s.deleteBackendsFromCacheLocked(svc)
	scopedLog := log.WithFields(logrus.Fields{
		logfields.ServiceID: svc.frontend.ID,
		logfields.ServiceIP: svc.frontend.L3n4Addr,
		logfields.Backends:  svc.backends,
	})
	scopedLog.Debug("Deleting service")

	if err := s.lbmap.DeleteService(svc.frontend, len(svc.backends),
		svc.useMaglev(), svc.svcNatPolicy); err != nil {
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
		s.lbmap.DeleteBackendByID(id)
	}
	if err := DeleteID(uint32(svc.frontend.ID)); err != nil {
		return fmt.Errorf("Unable to release service ID %d: %w", svc.frontend.ID, err)
	}

	// Delete managed neighbor entries of the LB
	if option.Config.DatapathMode == datapathOpt.DatapathModeLBOnly {
		s.deleteBackendNeighbors(obsoleteBackends)
	}

	if svc.healthcheckFrontendHash != "" {
		healthSvc := s.svcByHash[svc.healthcheckFrontendHash]
		if healthSvc != nil {
			s.deleteServiceLocked(healthSvc)
		}
	}

	if option.Config.EnableHealthCheckNodePort {
		s.healthServer.DeleteService(lb.ID(svc.frontend.ID))
	}

	metrics.ServicesEventsCount.WithLabelValues("delete").Inc()
	s.notifyMonitorServiceDelete(svc.frontend.ID)

	return nil
}

func (s *Service) updateBackendsCacheLocked(svc *svcInfo, backends []*lb.Backend) (
	[]*lb.Backend, []*lb.Backend, []lb.BackendID, error,
) {
	obsoleteBackends := []*lb.Backend{}       // not used by any svc
	obsoleteSVCBackendIDs := []lb.BackendID{} // removed from the svc, but might be used by other svc
	newBackends := []*lb.Backend{}            // previously not used by any svc
	backendSet := map[string]struct{}{}

	for i, backend := range backends {
		hash := backend.L3n4Addr.Hash()
		backendSet[hash] = struct{}{}

		if b, found := svc.backendByHash[hash]; !found {
			if s.backendRefCount.Add(hash) {
				id, err := AcquireBackendID(backend.L3n4Addr)
				if err != nil {
					s.backendRefCount.Delete(hash)
					return nil, nil, nil, fmt.Errorf("Unable to acquire backend ID for %q: %w",
						backend.L3n4Addr, err)
				}
				backends[i].ID = id
				backends[i].Weight = backend.Weight
				newBackends = append(newBackends, backends[i])
				s.backendByHash[hash] = backends[i].DeepCopy()
			} else {
				backends[i].ID = s.backendByHash[hash].ID
			}
		} else {
			// We observed this backend, hence let's remove it from the list
			// of the restored ones.
			svc.restoredBackendHashes.Delete(hash)

			backends[i].ID = b.ID
			// Backend state can either be updated via kubernetes events,
			// or service API. If the state update is coming via kubernetes events,
			// then we need to update the internal state. Currently, the only state
			// update in this case is for the terminating state or when backend
			// weight has changed. All other state updates happen via the API
			// (UpdateBackendsState) in which case we need to set the backend state
			// to the saved state.
			switch {
			case backends[i].State == lb.BackendStateTerminating &&
				b.State != lb.BackendStateTerminating:
				b.State = backends[i].State
				// Update the persisted backend state in BPF maps.
				if err := s.lbmap.UpdateBackendWithState(backends[i]); err != nil {
					return nil, nil, nil, fmt.Errorf("failed to update backend %+v: %w",
						backends[i], err)
				}
			case backends[i].Weight != b.Weight:
				// Update the cached weight as weight has changed
				b.Weight = backends[i].Weight
				// Update but do not persist the state as backend might be set as active
				// only temporarily for specific service
				b.State = backends[i].State
			default:
				// Set the backend state to the saved state.
				backends[i].State = b.State
			}
		}
		svc.backendByHash[hash] = backends[i]
	}

	for hash, backend := range svc.backendByHash {
		if _, found := backendSet[hash]; !found {
			if svc.restoredBackendHashes.Has(hash) {
				// Don't treat backends restored from the datapath and not yet observed as
				// obsolete, because that would cause connections targeting those backends
				// to be dropped in case we haven't fully synchronized yet.
				backends = append(backends, backend)
				continue
			}

			obsoleteSVCBackendIDs = append(obsoleteSVCBackendIDs, backend.ID)
			if s.backendRefCount.Delete(hash) {
				DeleteBackendID(backend.ID)
				delete(s.backendByHash, hash)
				obsoleteBackends = append(obsoleteBackends, backend)
			}
			delete(svc.backendByHash, hash)
		}
	}

	svc.backends = backends
	return newBackends, obsoleteBackends, obsoleteSVCBackendIDs, nil
}

func (s *Service) deleteBackendsFromCacheLocked(svc *svcInfo) ([]lb.BackendID, []*lb.Backend) {
	obsoleteBackendIDs := []lb.BackendID{}
	obsoleteBackends := []*lb.Backend{}

	for hash, backend := range svc.backendByHash {
		if s.backendRefCount.Delete(hash) {
			DeleteBackendID(backend.ID)
			obsoleteBackendIDs = append(obsoleteBackendIDs, backend.ID)
			obsoleteBackends = append(obsoleteBackends, backend.DeepCopy())
		}
	}

	return obsoleteBackendIDs, obsoleteBackends
}

func (s *Service) notifyMonitorServiceUpsert(frontend lb.L3n4AddrID, backends []*lb.Backend,
	svcType lb.SVCType, svcExtTrafficPolicy, svcIntTrafficPolicy lb.SVCTrafficPolicy, svcName, svcNamespace string,
) {
	id := uint32(frontend.ID)
	fe := monitorAPI.ServiceUpsertNotificationAddr{
		IP:   frontend.AddrCluster.AsNetIP(),
		Port: frontend.Port,
	}

	be := make([]monitorAPI.ServiceUpsertNotificationAddr, 0, len(backends))
	for _, backend := range backends {
		b := monitorAPI.ServiceUpsertNotificationAddr{
			IP:   backend.AddrCluster.AsNetIP(),
			Port: backend.Port,
		}
		be = append(be, b)
	}

	msg := monitorAPI.ServiceUpsertMessage(id, fe, be, string(svcType), string(svcExtTrafficPolicy), string(svcIntTrafficPolicy), svcName, svcNamespace)
	s.monitorAgent.SendEvent(monitorAPI.MessageTypeAgent, msg)
}

func (s *Service) notifyMonitorServiceDelete(id lb.ID) {
	s.monitorAgent.SendEvent(monitorAPI.MessageTypeAgent, monitorAPI.ServiceDeleteMessage(uint32(id)))
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

	return svc.svcName.Namespace, svc.svcName.Name, true
}

// isWildcardAddr returns true if given frontend is used for wildcard svc lookups
// (by bpf_sock).
func isWildcardAddr(frontend lb.L3n4AddrID) bool {
	if frontend.IsIPv6() {
		return cmtypes.MustParseAddrCluster("::").Equal(frontend.AddrCluster)
	}
	return cmtypes.MustParseAddrCluster("0.0.0.0").Equal(frontend.AddrCluster)
}

// segregateBackends returns the list of active, preferred and nonActive backends to be
// added to the lbmaps. If EnableK8sTerminatingEndpoint and there are no active backends,
// segregateBackends will return all terminating backends as active.
func segregateBackends(backends []*lb.Backend) (preferredBackends map[string]*lb.Backend,
	activeBackends map[string]*lb.Backend, nonActiveBackends []lb.BackendID,
) {
	preferredBackends = make(map[string]*lb.Backend)
	activeBackends = make(map[string]*lb.Backend, len(backends))

	for _, b := range backends {
		// Separate active from non-active backends so that they won't be selected
		// to serve new requests, but can be restored after agent restart. Non-active backends
		// are kept in the affinity and backend maps so that existing connections
		// are able to terminate gracefully. Such backends would either be cleaned-up
		// when the backends are deleted, or they could transition to active state.
		if b.State == lb.BackendStateActive {
			activeBackends[b.String()] = b
			// keep another list of preferred backends if available
			if b.Preferred {
				preferredBackends[b.String()] = b
			}
		} else {
			nonActiveBackends = append(nonActiveBackends, b.ID)
		}
	}
	// To avoid connections drops during rolling updates, Kubernetes defines a Terminating state on the EndpointSlices
	// that can be used to identify Pods that, despite being terminated, still can serve traffic.
	// In case that there are no Active backends, use the Backends in TerminatingState to answer new requests
	// and avoid traffic disruption until new active backends are created.
	// https://github.com/kubernetes/enhancements/tree/master/keps/sig-network/1669-proxy-terminating-endpoints
	if option.Config.EnableK8sTerminatingEndpoint && len(activeBackends) == 0 {
		nonActiveBackends = []lb.BackendID{}
		for _, b := range backends {
			if b.State == lb.BackendStateTerminating {
				activeBackends[b.String()] = b
			} else {
				nonActiveBackends = append(nonActiveBackends, b.ID)
			}
		}
	}
	return preferredBackends, activeBackends, nonActiveBackends
}

// SyncNodePortFrontends updates all NodePort services with a new set of frontend
// IP addresses.
func (s *Service) SyncNodePortFrontends(addrs sets.Set[netip.Addr]) error {
	s.Lock()
	defer s.Unlock()

	existingFEs := sets.New[netip.Addr]()
	removedFEs := make([]*svcInfo, 0)

	// Find all NodePort services by finding the surrogate services, and find
	// services with a removed frontend.
	v4Svcs := make([]*svcInfo, 0)
	v6Svcs := make([]*svcInfo, 0)
	for _, svc := range s.svcByID {
		if svc.svcType != lb.SVCTypeNodePort {
			continue
		}

		switch svc.frontend.AddrCluster.Addr() {
		case netip.IPv4Unspecified():
			v4Svcs = append(v4Svcs, svc)
		case netip.IPv6Unspecified():
			v6Svcs = append(v6Svcs, svc)
		default:
			addr := svc.frontend.AddrCluster.Addr()
			existingFEs.Insert(addr)
			if _, ok := addrs[addr]; !ok {
				removedFEs = append(removedFEs, svc)
			}
		}
	}

	// Delete the services of the removed frontends
	for _, svc := range removedFEs {
		log := log.WithField(logfields.K8sNamespace, svc.svcName.Namespace).
			WithField(logfields.K8sSvcName, svc.svcName.Name).
			WithField(logfields.L3n4Addr, svc.frontend.L3n4Addr)

		if err := s.deleteServiceLocked(svc); err != nil {
			return fmt.Errorf("delete service: %w", err)
		} else {
			log.Debug("Deleted nodeport service of a removed frontend")
		}
	}

	// Create services for the new frontends
	for addr := range addrs {
		if !existingFEs.Has(addr) {
			// No services for this frontend, create them.
			svcs := v4Svcs
			if addr.Is6() {
				svcs = v6Svcs
			}
			for _, svcInfo := range svcs {
				fe := lb.NewL3n4AddrID(
					svcInfo.frontend.Protocol,
					cmtypes.AddrClusterFrom(addr, svcInfo.frontend.AddrCluster.ClusterID()),
					svcInfo.frontend.Port,
					svcInfo.frontend.Scope,
					0,
				)
				svc := svcInfo.deepCopyToLBSVC()
				svc.Frontend = *fe

				log := log.WithField(logfields.K8sNamespace, svc.Name.Namespace).
					WithField(logfields.K8sSvcName, svc.Name.Name).
					WithField(logfields.L3n4Addr, svc.Frontend.L3n4Addr)
				_, _, err := s.upsertService(svc)
				if err != nil {
					return fmt.Errorf("upsert service: %w", err)
				} else {
					log.Debug("Created nodeport service for new frontend")
				}
			}
		}
	}
	return nil
}

func backendToNode(b *lb.Backend) *nodeTypes.Node {
	return &nodeTypes.Node{
		Name: fmt.Sprintf("backend-%s", b.L3n4Addr.AddrCluster.AsNetIP()),
		IPAddresses: []nodeTypes.Address{{
			Type: addressing.NodeInternalIP,
			IP:   b.L3n4Addr.AddrCluster.AsNetIP(),
		}},
	}
}

func (s *Service) upsertBackendNeighbors(newBackends, oldBackends []*lb.Backend) {
	for _, b := range newBackends {
		s.backendDiscovery.InsertMiscNeighbor(backendToNode(b))
	}
	s.deleteBackendNeighbors(oldBackends)
}

func (s *Service) deleteBackendNeighbors(obsoleteBackends []*lb.Backend) {
	for _, b := range obsoleteBackends {
		s.backendDiscovery.DeleteMiscNeighbor(backendToNode(b))
	}
}
