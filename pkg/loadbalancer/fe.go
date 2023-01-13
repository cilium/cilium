package loadbalancer

type FE interface {
	ServiceName() ServiceName
	Address() *L3n4Addr
	ToSVC() *SVC
}

type CommonFE struct {
	Name                      ServiceName
	ExtTrafficPolicy          SVCTrafficPolicy // Service traffic policy
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
		ExtTrafficPolicy:          fe.ExtTrafficPolicy,
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
		ExtTrafficPolicy:          fe.ExtTrafficPolicy,
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
		ExtTrafficPolicy:          fe.ExtTrafficPolicy,
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
		ExtTrafficPolicy:          fe.ExtTrafficPolicy,
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
