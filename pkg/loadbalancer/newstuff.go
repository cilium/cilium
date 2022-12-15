package loadbalancer

import "github.com/cilium/cilium/pkg/cidr"

// TODO: Where does Frontend and Backend types live?
// pkg/loadbalancer might not be so bad as it's shared by all layers.
// TODO: remove 'type SVC struct'.
// TODO: should things like L7LB fields be additional type specific options? seems like Frontend should be a sum-type. likely premature to do that.
type Frontend struct {
	Address                   L3n4Addr
	Type                      SVCType
	TrafficPolicy             SVCTrafficPolicy // Service traffic policy
	NatPolicy                 SVCNatPolicy     // Service NAT 46/64 policy
	SessionAffinity           bool
	SessionAffinityTimeoutSec uint32
	HealthCheckNodePort       uint16 // Service health check node port
	Name                      ServiceName
	LoadBalancerSourceRanges  []*cidr.CIDR
	L7LBProxyPort             uint16   // Non-zero for L7 LB services
	L7LBFrontendPorts         []string // Non-zero for L7 LB frontend service ports
	LoopbackHostport          bool
}

// Alternative:
type FE interface {
	isFE()

	ServiceName() ServiceName
}

type CommonFE struct {
	Name ServiceName
}

func (c CommonFE) ServiceName() ServiceName { return c.Name }
func (CommonFE) isFE()                      {}

type FENodePort struct {
	CommonFE
	/* has no address as it's assigned by datapath */

	// TODO: which ones share these?
	TrafficPolicy             SVCTrafficPolicy // Service traffic policy
	NatPolicy                 SVCNatPolicy     // Service NAT 46/64 policy
	SessionAffinity           bool
	SessionAffinityTimeoutSec uint32
	HealthCheckNodePort       uint16 // Service health check node port
}

type FEClusterIP struct {
	CommonFE

	Address L3n4Addr
}

type FEL7Proxy struct {
	CommonFE
	ProxyPort uint16

	// The frontends that are redirected to the proxy. Should be left empty as
	// it is filled in by ServiceManager.
	RedirectedFrontends []FE
}

// TODO: Scoped to svc/.../...?
// TODO: The backends are selected by pod labels and are not the same set as the
// backends for the service, so this is a weirdo with its own backends and
// if selected all the other backends for this service are ignored.
type FELocalRedirectService struct {
	CommonFE

	// The frontends that are redirected to the local pods. Should be left empty as
	// it is filled in by ServiceManager.
	RedirectedFrontends []FE

	LocalBackends []*Backend
}

// TODO: Scoped to lrp/.../... ?
type FELocalRedirectAddress struct {
	CommonFE

	// TODO: ServiceManager will need to determine who wins when frontend
	// addresses overlap. E.g. need to first reconcile on service name the
	// winning frontends, and then globally on address.
	Address L3n4Addr

	LocalBackends []*Backend
}

/*
// Backend represents load balancer backend.
type Backend struct {
	// FEPortName is the frontend port name. This is used to filter backends sending to EDS.
	FEPortName string
	// Weight of backend
	Weight uint16
	// Node hosting this backend. This is used to determine backends local to
	// a node.
	NodeName string
	.L3n4Addr
	// State of the backend for load-balancing service traffic
	State loadbalancer.BackendState
	// Preferred indicates if the healthy backend is preferred
	Preferred loadbalancer.Preferred
}
*/
