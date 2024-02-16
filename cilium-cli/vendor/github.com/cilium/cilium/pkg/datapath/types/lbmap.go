// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package types

import (
	"net"
	"sort"

	"github.com/cilium/cilium/pkg/cidr"
	"github.com/cilium/cilium/pkg/loadbalancer"
)

// LBMap is the interface describing methods for manipulating service maps.
type LBMap interface {
	UpsertService(*UpsertServiceParams) error
	UpsertMaglevLookupTable(uint16, map[string]*loadbalancer.Backend, bool) error
	IsMaglevLookupTableRecreated(bool) bool
	DeleteService(loadbalancer.L3n4AddrID, int, bool, loadbalancer.SVCNatPolicy) error
	AddBackend(*loadbalancer.Backend, bool) error
	UpdateBackendWithState(*loadbalancer.Backend) error
	DeleteBackendByID(loadbalancer.BackendID) error
	AddAffinityMatch(uint16, loadbalancer.BackendID) error
	DeleteAffinityMatch(uint16, loadbalancer.BackendID) error
	UpdateSourceRanges(uint16, []*cidr.CIDR, []*cidr.CIDR, bool) error
	DumpServiceMaps() ([]*loadbalancer.SVC, []error)
	DumpBackendMaps() ([]*loadbalancer.Backend, error)
	DumpAffinityMatches() (BackendIDByServiceIDSet, error)
	DumpSourceRanges(bool) (SourceRangeSetByServiceID, error)
	ExistsSockRevNat(cookie uint64, addr net.IP, port uint16) bool
}

type UpsertServiceParams struct {
	ID   uint16
	IP   net.IP
	Port uint16

	// PreferredBackends is a subset of ActiveBackends
	// Note: this is only used in clustermesh with service affinity annotation.
	PreferredBackends         map[string]*loadbalancer.Backend
	ActiveBackends            map[string]*loadbalancer.Backend
	NonActiveBackends         []loadbalancer.BackendID
	PrevBackendsCount         int
	IPv6                      bool
	Type                      loadbalancer.SVCType
	NatPolicy                 loadbalancer.SVCNatPolicy
	ExtLocal                  bool
	IntLocal                  bool
	Scope                     uint8
	SessionAffinity           bool
	SessionAffinityTimeoutSec uint32
	CheckSourceRange          bool
	UseMaglev                 bool
	L7LBProxyPort             uint16                   // Non-zero for L7 LB services
	Name                      loadbalancer.ServiceName // Fully qualified name of the service
	LoopbackHostport          bool
}

// GetOrderedBackends returns an ordered list of backends with all the sorted
// preferred backend followed by active and non-active backends.
// Encapsulates logic to be also used in unit tests.
func (p *UpsertServiceParams) GetOrderedBackends() []loadbalancer.BackendID {
	backendIDs := make([]loadbalancer.BackendID, 0, len(p.ActiveBackends)+len(p.NonActiveBackends))
	for _, b := range p.ActiveBackends {
		backendIDs = append(backendIDs, b.ID)
	}

	preferredMap := map[loadbalancer.BackendID]struct{}{}
	for _, b := range p.PreferredBackends {
		preferredMap[b.ID] = struct{}{}
	}

	// Map iterations are non-deterministic so sort the backends by their IDs
	// in order to maintain the same order before they are populated in BPF maps.
	// This will minimize disruption to existing connections to the backends in the datapath.
	sort.Slice(backendIDs, func(i, j int) bool {
		// compare preferred flags of two backend IDs
		_, firstPreferred := preferredMap[backendIDs[i]]
		_, secondPreferred := preferredMap[backendIDs[j]]

		if firstPreferred && secondPreferred {
			return backendIDs[i] < backendIDs[j]
		}

		if firstPreferred {
			return true
		}

		if secondPreferred {
			return false
		}

		return backendIDs[i] < backendIDs[j]
	})

	// Add the non-active backends to the end of preferred/active backends list so that they are
	// not considered while selecting backends to load-balance service traffic.
	if len(p.NonActiveBackends) > 0 {
		backendIDs = append(backendIDs, p.NonActiveBackends...)
	}

	return backendIDs
}

// BackendIDByServiceIDSet is the type of a set for checking whether a backend
// belongs to a given service
type BackendIDByServiceIDSet map[uint16]map[loadbalancer.BackendID]struct{} // svc ID => backend ID

type SourceRangeSetByServiceID map[uint16][]*cidr.CIDR // svc ID => src range CIDRs
