// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package service

import (
	"net/netip"

	"k8s.io/apimachinery/pkg/util/sets"

	"github.com/cilium/cilium/pkg/k8s"
	lb "github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/time"
)

var _ ServiceManager = &Service{}

// ServiceManager provides an interface for service related operations.
// It is implemented by service handler which main responsibility is to reflect
// service-related changes into BPF maps used by datapath BPF programs.
type ServiceManager interface {
	// DeleteService removes the given service.
	DeleteService(frontend lb.L3n4Addr) (bool, error)

	// DeleteServiceByID removes a service identified by the given ID.
	DeleteServiceByID(id lb.ServiceID) (bool, error)

	// GetCurrentTs retrieves the current timestamp.
	GetCurrentTs() time.Time

	// GetDeepCopyServices returns a deep-copy of all installed services.
	GetDeepCopyServices() []*lb.SVC

	// GetServiceIDs returns a list of IDs of all installed services.
	GetServiceIDs() []lb.ServiceID

	// GetDeepCopyServiceByFrontend returns a deep-copy of the service that matches the Frontend address.
	GetDeepCopyServiceByFrontend(frontend lb.L3n4Addr) (*lb.SVC, bool)

	// GetDeepCopyServiceByID returns a deep-copy of a service identified with the given ID.
	GetDeepCopyServiceByID(id lb.ServiceID) (*lb.SVC, bool)

	// GetLastUpdatedTs retrieves the last updated timestamp.
	GetLastUpdatedTs() time.Time

	// GetServiceNameByAddr looks up service by IP/port. Hubble uses this function
	// to annotate flows with service information.
	GetServiceNameByAddr(addr lb.L3n4Addr) (string, string, bool)

	// InitMaps opens or creates BPF maps used by services.
	InitMaps(ipv6, ipv4, sockMaps, restore bool) error

	// RegisterL7LBServiceRedirect makes the given service to be locally redirected to the given proxy port.
	RegisterL7LBServiceRedirect(serviceName lb.ServiceName, resourceName L7LBResourceName, proxyPort uint16, frontendPorts []uint16) error

	// DeregisterL7LBServiceRedirect deregisters a Service from being redirected to a L7 LB.
	DeregisterL7LBServiceRedirect(serviceName lb.ServiceName, resourceName L7LBResourceName) error

	// RegisterL7LBServiceBackendSync registers a backend sync registration for the service.
	RegisterL7LBServiceBackendSync(serviceName lb.ServiceName, backendSyncRegistration BackendSyncer) error

	// DeregisterL7LBServiceBackendSync deregisters a backend sync registration for the service.
	DeregisterL7LBServiceBackendSync(serviceName lb.ServiceName, backendSyncRegistration BackendSyncer) error

	// RestoreServices restores services from BPF maps.
	RestoreServices() error

	// SyncNodePortFrontends updates all NodePort service frontends with a new set of frontend
	// IP addresses.
	SyncNodePortFrontends(sets.Set[netip.Addr]) error

	// SyncWithK8sFinished removes services which we haven't heard about during
	// a sync period of cilium-agent's k8s service cache.
	SyncWithK8sFinished(localOnly bool, localServices sets.Set[k8s.ServiceID]) (stale []k8s.ServiceID, err error)

	// UpdateBackendsState updates all the service(s) with the updated state of
	// the given backends, and returns the updated services.
	// It also persists the updated backend states to the BPF maps.
	UpdateBackendsState(backends []*lb.Backend) ([]lb.L3n4Addr, error)

	// UpsertService inserts or updates the given service.
	UpsertService(*lb.SVC) (bool, lb.ID, error)

	// TerminateUDPConnectionsToBackend terminates UDP connections to the passed
	// backend with address when socket-LB is enabled.
	TerminateUDPConnectionsToBackend(l3n4Addr *lb.L3n4Addr)
}
