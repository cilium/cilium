package servicemanager

import (
	"context"

	"github.com/cilium/cilium/pkg/loadbalancer"
)

// TODO: or call it "ServiceState"?
type Event interface {
	Name() loadbalancer.ServiceName

	// TODO: Should just implement Iter[T] instead. Double-check what the Go 2.0 situation regarding
	// iterators is.
	ForEachActiveFrontend(func(Frontend))
	ForEachBackend(func(Backend))
}

// TODO should be LoadBalancerManager or something.
type ServiceManager interface {
	NewHandle(name string) ServiceHandle
}

type ServiceHandle interface {
	Synchronized()

	// TODO pass Frontend and Backend by value at this boundary and then pass them internally
	// by pointer?

	// TODO data validation and return error from upserts? alternatively it'd probably be cleaner
	// to have validating smart constructors for Frontend and Backend.

	// TODO combined Upsert for frontend + backends to avoid taking action too early?

	// TODO can drop ServiceName from UpsertFrontend as it's same as Frontend.Name.

	UpsertFrontend(id loadbalancer.ServiceName, frontend *loadbalancer.Frontend)
	DeleteFrontend(id loadbalancer.ServiceName, addr loadbalancer.L3n4Addr, svcType loadbalancer.SVCType)
	UpsertBackends(id loadbalancer.ServiceName, backends ...*loadbalancer.Backend)
	DeleteBackends(id loadbalancer.ServiceName, addrs ...loadbalancer.L3n4Addr)

	UpsertFE(fe loadbalancer.FE)
	DeleteFE(fe loadbalancer.FE)

	// Events returns a channel of events.
	// If emitCurrent is true, the current state of each service is emitted.
	// Filters by ServiceName if non-nil.
	//
	// TODO: Use cases for this are:
	// * L7 Proxy (for pushing backends to envoy)
	// * API handler for listing services (though should have Iter() and Get() instead)
	// * ???
	Events(ctx context.Context, emitCurrent bool, name *loadbalancer.ServiceName) <-chan Event

	// Or alternatively for L7 proxy could do something simpler like:
	//OnServiceChange(id ServiceID, fn func(Event)) (unsubscribe func())
	//
	//or resource.ObjectTracker style:
	//Tracker(context.Context) ServiceTracker
	//type ServiceTracker interface {
	//  Events() <-chan Event
	//  Track(ServiceID)
	//  Untrack(ServiceID)
	//}
}
