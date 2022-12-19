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

func isType[T lb.FE](fe lb.FE) bool {
	switch fe.(type) {
	case T:
		return true
	}
	return false
}

func isVirtual(fe lb.FE) bool {
	return isType[*lb.FEL7Proxy](fe) || isType[*lb.FELocalRedirectService](fe)
}

func not[T any](pred func(T) bool) func(T) bool {
	return func(x T) bool {
		return !pred(x)
	}
}

func or[T any](a func(T) bool, b func(T) bool) func(T) bool {
	return func(x T) bool {
		return a(x) || b(x)
	}
}

// the rules:
// - all frontends and backends are accepted, so that data is not dropped.
// - there may be conflicts (both L7 and LRP), and in those cases the service
//   manager will be in degraded state and picks arbitrarily which one wins.
// - if there is ;w
// 


// reduceFrontends takes all frontends under a given service name and reduces
// them to the list of active ones.
func reduceFEs(name ServiceName, fes []lb.FE) (out []lb.FE) {
	// Local redirections are considered first.
	redirs, fes := partition(fes, isType[*lb.FELocalRedirectService])
	if len(redirs) > 0 { // TODO: what if many?
		redir := redirs[0].(*lb.FELocalRedirectService)
		for _, fe := range fes {
			out = append(out, &lb.FELocalRedirectService{
				     CommonFE: redir.CommonFE,
				     Inherits: fe,
				     Pods: redir.Pods,
			})
		}
		return
	}

	// TODO: resolve overlapping frontend addresses? Should UpsertFrontend already
	// reject them or should we just revolve them by priority and report per-frontend
	// status to the source (e.g. by updating Service.Status)?

	return fes
}

