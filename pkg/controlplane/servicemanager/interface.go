package servicemanager

import (
	"github.com/cilium/cilium/pkg/loadbalancer"
)

// TODO should be LoadBalancerManager or something.
type ServiceManager interface {
	NewHandle(name string) ServiceHandle

	// TODO: Lookups without a handle?
}

type ServiceHandle interface {
	Synchronized()

	// TODO: If we assume all LBMap errors are handled internally
	// with retrying, are there any errors left to be reported?
	// We probably want to validate the data very early as it'd allow e.g.
	// updating k8s object status with a validation error. Handling invalid
	// data here is too late... though that might require k8s handler to know
	// about load balancing configuration etc. Perhaps DatapathLoadBalancing.Upsert could
	// return errors on invalid data but not on anything else and those we can bubble up
	// to e.g. k8s handler, which can then inform the user that it was invalid request.

	// UpsertService inserts or updates a service with a matching frontend and type.
	//
	// If a service exists with the same frontend, then the highest priority one based
	// on service type will be used in datapath. Lower priority one is activated when a
	// higher priority service is removed.
	Upsert(id loadbalancer.FrontendID, frontend *loadbalancer.Frontend, backends []*loadbalancer.Backend)

	Delete(id loadbalancer.FrontendID)

	// Iter iterates over frontends and the associated backends.
	// Only the primary frontend is returned.
	Iter() Iter2[loadbalancer.Frontend, []loadbalancer.Backend]
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
