package servicemanager

import (
	"golang.org/x/exp/slices"

	"github.com/cilium/cilium/pkg/container"
	datapathlb "github.com/cilium/cilium/pkg/datapath/lb"
	lb "github.com/cilium/cilium/pkg/loadbalancer"
)

// serviceEntry contains a set of frontends and backends associated with a specific
// service.
type serviceEntry struct {
	// metadata? creation time? handle that created it?

	overrideLocalRedirect *overrideLocalRedirect
	overrideProxyRedirect *overrideProxyRedirect

	// TODO: Making the assumption here that it's better to store these linearly in
	// an array at the cost of linear search. Validate this assumption with few
	// and many frontends and backends, and compare CPU, memory and GC cost of this
	// against storing these as maps.

	// TODO: Check that're fine with regards to 22f5b525ebe1a19f0c9d9d106ff8efa11a9fdf8a.
	// Commit there talks about holding onto old []lb.Backend due to notifyMonitorServiceUpsert,
	// but don't quite see how that happens.

	frontends l3n4Set[lb.FE]
	backends  l3n4Set[*lb.Backend]

	observers container.Set[*serviceHandle]
}

func (e *serviceEntry) isZero() bool {
	return len(e.frontends) == 0 &&
		len(e.backends) == 0 &&
		e.overrideLocalRedirect == nil &&
		e.overrideProxyRedirect == nil &&
		len(e.observers) == 0
}

func (e *serviceEntry) apply(dp datapathlb.LoadBalancer) {
	if e.overrideLocalRedirect != nil {
		e.overrideLocalRedirect.apply(e, dp)
		return
	}
	if e.overrideProxyRedirect != nil {
		e.overrideProxyRedirect.apply(e, dp)
		return
	}

	for _, fe := range e.frontends {
		svc := fe.ToSVC()
		svc.Backends = e.backends
		dp.Upsert(svc)
	}
}

type addresser interface {
	Address() *lb.L3n4Addr
}

type l3n4Set[T addresser] []T

func (s *l3n4Set[T]) upsert(x T) {
	for i := range *s {
		if (*s)[i].Address().DeepEqual(x.Address()) {
			(*s)[i] = x
			return
		}
	}
	(*s) = append((*s), x)
}

func (s *l3n4Set[T]) delete(addr *lb.L3n4Addr) {
	for i := range *s {
		if (*s)[i].Address().DeepEqual(addr) {
			(*s) = slices.Delete((*s), i, i+1)
			return
		}
	}
}

type overrideProxyRedirect struct {
	owner     *serviceHandle
	proxyPort uint16
}

func (o *overrideProxyRedirect) apply(e *serviceEntry, dp datapathlb.LoadBalancer) {
	for _, fe := range e.frontends {
		svc := fe.ToSVC()
		svc.Backends = e.backends
		svc.L7LBProxyPort = o.proxyPort
		dp.Upsert(svc)
	}
}

type overrideLocalRedirect struct {
	localBackends []*lb.Backend
}

func (o *overrideLocalRedirect) apply(e *serviceEntry, dp datapathlb.LoadBalancer) {
	// FIXME does local service redirect to apply to all frontends equally?
	for _, fe := range e.frontends {
		svc := fe.ToSVC()
		svc.Backends = o.localBackends
		dp.Upsert(svc)
	}
}
