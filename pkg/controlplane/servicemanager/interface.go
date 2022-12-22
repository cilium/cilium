package servicemanager

import (
	lb "github.com/cilium/cilium/pkg/loadbalancer"
)

type BackendsChanged struct {
	Name     lb.ServiceName
	Backends []lb.Backend
}

type ServiceManager interface {
	NewHandle(name string) ServiceHandle
}

type ServiceHandle interface {
	Close()
	Synchronized()

	UpsertFrontend(fe lb.FE)
	DeleteFrontend(fe lb.FE)

	UpsertBackends(name lb.ServiceName, backends ...lb.Backend)
	DeleteBackends(name lb.ServiceName, addrs ...lb.L3n4Addr)

	SetProxyRedirect(name lb.ServiceName, proxyPort uint16, backendChanges chan<- BackendsChanged)
	RemoveProxyRedirect(name lb.ServiceName)

	SetLocalRedirect(name lb.ServiceName, localBackends []lb.Backend)
	RemoveLocalRedirect(name lb.ServiceName)
}
