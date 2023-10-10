// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package service

import (
	"github.com/cilium/cilium/pkg/datapath/types"
	"github.com/cilium/cilium/pkg/k8s"
	lb "github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/time"
)

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

	// RegisterL7LBService makes the given service to be locally forwarded to th given proxy port.
	RegisterL7LBService(serviceName, resourceName lb.ServiceName, ports []string, proxyPort uint16) error

	// RegisterL7LBServiceBackendSync synchronizes the backends of a service to Envoy.
	RegisterL7LBServiceBackendSync(serviceName, resourceName lb.ServiceName, ports []string) error

	// RemoveL7LBService removes a service from L7 load balancing.
	RemoveL7LBService(serviceName, resourceName lb.ServiceName) error

	// RestoreServices restores services from BPF maps.
	RestoreServices() error

	// SyncServicesOnDeviceChange finds and adds missing load-balancing entries for new devices.
	SyncServicesOnDeviceChange(nodeAddressing types.NodeAddressing)

	// SyncWithK8sFinished removes services which we haven't heard about during
	// a sync period of cilium-agent's k8s service cache.
	SyncWithK8sFinished(ensurer func(k8s.ServiceID, *lock.StoppableWaitGroup) bool) error

	// UpdateBackendsState updates all the service(s) with the updated state of
	// the given backends. It also persists the updated backend states to the BPF maps.
	UpdateBackendsState(backends []*lb.Backend) error

	// UpsertService inserts or updates the given service.
	UpsertService(*lb.SVC) (bool, lb.ID, error)
}
