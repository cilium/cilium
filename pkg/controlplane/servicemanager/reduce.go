package servicemanager

import (
	lb "github.com/cilium/cilium/pkg/loadbalancer"
)

func filter[T any](xs []T, f func(T) bool) []T {
	out := []T{}
	for i := range xs {
		if f(xs[i]) {
			out = append(out, xs[i])
		}
	}
	return out
}

func partition[T any](xs []T, f func(T) bool) ([]T, []T) {
	left, right := []T{}, []T{}
	for i := range xs {
		if f(xs[i]) {
			left = append(left, xs[i])
		} else {
			right = append(right, xs[i])
		}
	}
	return left, right
}

func byType[T lb.FE](fe lb.FE) bool {
	_, ok := fe.(T)
	return ok
}

func or[T any](a func(T) bool, b func(T) bool) func(T) bool {
	return func(x T) bool {
		return a(x) || b(x)
	}
}

// reduceFrontends takes all frontends under a given service name and reduces
// them to the list of active ones.
func reduceFrontends(name ServiceName, frontends []lb.FE) []lb.FE {
	// Local redirections are considered first.
	redirs, frontends := partition(frontends, byType[lb.FELocalRedirectService])
	if len(redirs) > 0 { // TODO: what if many?
		fe := redirs[0].(lb.FELocalRedirectService)
		// TODO filter out L7?
		fe.RedirectedFrontends = frontends
		return []lb.FE{fe}
	}

	// Then L7
	l7s, frontends := partition(frontends, byType[lb.FEL7Proxy])
	if len(l7s) > 0 { // TODO: what if many?
		fe := redirs[0].(lb.FEL7Proxy)
		fe.RedirectedFrontends = frontends
		return []lb.FE{fe}
	}

	// TODO: resolve overlapping frontend addresses? Should UpsertFrontend already
	// reject them or should we just revolve them by priority and report per-frontend
	// status to the source (e.g. by updating Service.Status)?

	return frontends
}
