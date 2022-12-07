package servicemanager

import (
	"github.com/cilium/cilium/pkg/cidr"
	"github.com/cilium/cilium/pkg/loadbalancer"
)

type ServiceManager interface {
	NewHandle(name string) ServiceHandle

	// TODO: Lookups without a handle?
}

// A service is fully identified by the frontend and its type.
// NodePort services have a port, but no L3 address.
type FrontendID struct {
	Frontend loadbalancer.L3n4Addr
	Type     loadbalancer.SVCType
}

type Frontend struct {
	Address                   loadbalancer.L3n4Addr
	Type                      loadbalancer.SVCType
	TrafficPolicy             loadbalancer.SVCTrafficPolicy // Service traffic policy
	NatPolicy                 loadbalancer.SVCNatPolicy     // Service NAT 46/64 policy
	SessionAffinity           bool
	SessionAffinityTimeoutSec uint32
	HealthCheckNodePort       uint16                   // Service health check node port
	Name                      loadbalancer.ServiceName // Fully qualified service name
	LoadBalancerSourceRanges  []*cidr.CIDR
	L7LBProxyPort             uint16   // Non-zero for L7 LB services
	L7LBFrontendPorts         []string // Non-zero for L7 LB frontend service ports
	LoopbackHostport          bool
}

// Backend represents load balancer backend.
type Backend struct {
	// FEPortName is the frontend port name. This is used to filter backends sending to EDS.
	FEPortName string
	// Weight of backend
	Weight uint16
	// Node hosting this backend. This is used to determine backends local to
	// a node.
	NodeName string
	loadbalancer.L3n4Addr
	// State of the backend for load-balancing service traffic
	State loadbalancer.BackendState
	// Preferred indicates if the healthy backend is preferred
	Preferred loadbalancer.Preferred
}

type ServiceHandle interface {
	Close()
	Synchronized()

	// TODO: If we assume all LBMap errors are handled internally
	// with retrying, is there any errors left that could not be handled
	// by having e.g. a builder for ServiceV2 and BackendV2 that fails on
	// bad data?

	// UpsertService inserts or updates a service with a matching frontend and type.
	//
	// If a service exists with the same frontend, then the highest priority one based
	// on service type will be used in datapath. Lower priority one is activated when a
	// higher priority service is removed.
	UpsertFrontend(id FrontendID, frontend *Frontend, backends []*Backend)

	DeleteFrontend(id FrontendID)

	// TODO: DeepCopy? return by value?
	//GetServiceAndBackends(fe loadbalancer.L3n4Addr) (*Service, []*Backend, bool)

	// Iter iterates over frontends and the associated backends.
	// Only the primary frontends are returned.
	Iter() Iter2[Frontend, []Backend]
}

// as described in https://github.com/golang/go/discussions/54245
type Iter2[E1, E2 any] interface {
	Next() (E1, E2, bool)
}

// ServiceHandle.Iter() example:
// it := h.Iter()
// for svc, bes, ok := it.Next(); ok; svc, bes, ok = it.Next() {
//   ...
// }
//
// or if 54245 or similar is implemented we can do:
// for svc, bes := h.Iter {
// ...
// }
