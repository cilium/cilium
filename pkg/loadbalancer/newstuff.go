package loadbalancer

import "github.com/cilium/cilium/pkg/cidr"

// A service is fully identified by the frontend and its type.
// NodePort services have a port, but no L3 address.
type FrontendID struct {
	Address L3n4Addr
	Type    SVCType
}

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
	HealthCheckNodePort       uint16      // Service health check node port
	Name                      ServiceName // Fully qualified service name
	LoadBalancerSourceRanges  []*cidr.CIDR
	L7LBProxyPort             uint16   // Non-zero for L7 LB services
	L7LBFrontendPorts         []string // Non-zero for L7 LB frontend service ports
	LoopbackHostport          bool
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
