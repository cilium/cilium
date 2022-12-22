package loadbalancer

type FE interface {
	ServiceName() ServiceName
	Address() *L3n4Addr
	ToSVC() *SVC
}

type CommonFE struct {
	Name                      ServiceName
	TrafficPolicy             SVCTrafficPolicy // Service traffic policy
	NatPolicy                 SVCNatPolicy     // Service NAT 46/64 policy
	SessionAffinity           bool
	SessionAffinityTimeoutSec uint32
}

type FENodePort struct {
	CommonFE
	L4Addr              L4Addr
	Scope               uint8
	HealthCheckNodePort uint16 // Service health check node port
}

func (fe *FENodePort) Address() *L3n4Addr {
	return &L3n4Addr{
		L4Addr: fe.L4Addr,
		Scope:  fe.Scope,
	}
}

type FEClusterIP struct {
	CommonFE
	L3n4Addr L3n4Addr
}

func (fe *FEClusterIP) Address() *L3n4Addr {
	return &fe.L3n4Addr
}

func (fe *FEClusterIP) ToSVC() *SVC {
	svc := &SVC{
		Type:                      SVCTypeClusterIP,
		TrafficPolicy:             fe.TrafficPolicy,
		NatPolicy:                 fe.NatPolicy,
		SessionAffinity:           fe.SessionAffinity,
		SessionAffinityTimeoutSec: fe.SessionAffinityTimeoutSec,
		Name:                      fe.Name,
	}
	// FIXME change L3n4AddrID
	svc.Frontend.L3n4Addr = fe.L3n4Addr
	return svc
}

type FEExternalIPs struct {
	CommonFE
	L3n4Addr L3n4Addr
}

func (fe *FEExternalIPs) Address() *L3n4Addr {
	return &fe.L3n4Addr
}

func (fe *FEExternalIPs) ToSVC() *SVC {
	svc := &SVC{
		Type:                      SVCTypeClusterIP,
		TrafficPolicy:             fe.TrafficPolicy,
		NatPolicy:                 fe.NatPolicy,
		SessionAffinity:           fe.SessionAffinity,
		SessionAffinityTimeoutSec: fe.SessionAffinityTimeoutSec,
		Name:                      fe.Name,
	}
	// FIXME change L3n4AddrID
	svc.Frontend.L3n4Addr = fe.L3n4Addr
	return svc
}

type FELoadBalancer struct {
	CommonFE
	L3n4Addr L3n4Addr
	// TODO LoadBalancerSourceRanges
}

func (fe *FELoadBalancer) Address() *L3n4Addr {
	return &fe.L3n4Addr
}

func (fe *FELoadBalancer) ToSVC() *SVC {
	svc := &SVC{
		Type:                      SVCTypeClusterIP,
		TrafficPolicy:             fe.TrafficPolicy,
		NatPolicy:                 fe.NatPolicy,
		SessionAffinity:           fe.SessionAffinity,
		SessionAffinityTimeoutSec: fe.SessionAffinityTimeoutSec,
		Name:                      fe.Name,
	}
	// FIXME change L3n4AddrID
	svc.Frontend.L3n4Addr = fe.L3n4Addr
	return svc
}

type FELocalRedirectAddress struct {
	CommonFE
	L3n4Addr   L3n4Addr
	RedirectTo []*Backend
}

func (fe *CommonFE) ServiceName() ServiceName { return fe.Name }

func (fe *FENodePort) ToSVC() *SVC {
	svc := &SVC{
		Type:                      SVCTypeNodePort,
		TrafficPolicy:             fe.TrafficPolicy,
		NatPolicy:                 fe.NatPolicy,
		SessionAffinity:           fe.SessionAffinity,
		SessionAffinityTimeoutSec: fe.SessionAffinityTimeoutSec,
		HealthCheckNodePort:       fe.HealthCheckNodePort,
		Name:                      fe.Name,
	}
	svc.Frontend.Scope = fe.Scope
	svc.Frontend.L3n4Addr.L4Addr = fe.L4Addr
	return svc
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
