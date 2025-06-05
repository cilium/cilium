// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package service

import (
	"k8s.io/apimachinery/pkg/util/sets"

	"github.com/cilium/cilium/pkg/k8s"
	lb "github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/time"
)

// ServiceManager provides an interface for service related operations.
// It is implemented by service handler which main responsibility is to reflect
// service-related changes into BPF maps used by datapath BPF programs.
type ServiceManager interface {
	// GetCurrentTs retrieves the current timestamp.
	GetCurrentTs() time.Time

	// GetDeepCopyServices returns a deep-copy of all installed services.
	GetDeepCopyServices() []*lb.LegacySVC

	// GetServiceIDs returns a list of IDs of all installed services.
	GetServiceIDs() []lb.ServiceID

	// GetDeepCopyServiceByFrontend returns a deep-copy of the service that matches the Frontend address.
	GetDeepCopyServiceByFrontend(frontend lb.L3n4Addr) (*lb.LegacySVC, bool)

	// GetDeepCopyServiceByID returns a deep-copy of a service identified with the given ID.
	GetDeepCopyServiceByID(id lb.ServiceID) (*lb.LegacySVC, bool)

	// GetLastUpdatedTs retrieves the last updated timestamp.
	GetLastUpdatedTs() time.Time

	// GetServiceNameByAddr looks up service by IP/port. Hubble uses this function
	// to annotate flows with service information.
	GetServiceNameByAddr(addr lb.L3n4Addr) (string, string, bool)

	// SyncWithK8sFinished removes services which we haven't heard about during
	// a sync period of cilium-agent's k8s service cache.
	SyncWithK8sFinished(localOnly bool, localServices sets.Set[k8s.ServiceID]) (stale []k8s.ServiceID, err error)
}
