package servicemanager

import (
	lb "github.com/cilium/cilium/pkg/loadbalancer"
)

type Event struct {
	Name lb.ServiceName
	// TODO other info?
	Backends []lb.Backend
}

type ServiceManager interface {
	NewHandle(name string) ServiceHandle
}

type LocalRedirectConfig struct {
	FrontendPorts []uint16     // If not empty, only frontends with these ports will be redirected
	LocalBackends []lb.Backend // The node local backends to which traffic should be redirected
}

type ServiceHandle interface {
	Close()
	Synchronized()

	Observe(name lb.ServiceName)   // Start observing changes to specified service
	Unobserve(name lb.ServiceName) // Stop observing changes to specified service
	Events() <-chan Event          // Returns channel to which events for observed services are sent

	UpsertFrontend(fe lb.FE)
	DeleteFrontend(fe lb.FE)

	UpsertBackends(name lb.ServiceName, backends ...lb.Backend)
	DeleteBackends(name lb.ServiceName, addrs ...lb.L3n4Addr)

	SetProxyRedirect(name lb.ServiceName, proxyPort uint16)
	RemoveProxyRedirect(name lb.ServiceName)

	// FIXME: multiple LRPs might target the same ServiceName. Take a slice of configs and
	// have the LRP handler manage this?
	SetLocalRedirects(name lb.ServiceName, config LocalRedirectConfig)
	RemoveLocalRedirects(name lb.ServiceName)
}
