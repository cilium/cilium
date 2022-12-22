package servicemanager

/*
func filter[T any](xs []T, f func(T) bool) []T {
	out := []T{}
	for i := range xs {
		if f(xs[i]) {
			out = append(out, xs[i])
		}
	}
	return out
}

func partition[T lb.FE](xs []lb.FE) ([]T, []lb.FE) {
	left, right := []T{}, []lb.FE{}
	for i := range xs {
		switch x := xs[i].(type) {
		case T:
			left = append(left, x)
		default:
			right = append(right, x)
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


// TODO: Define this conversion as methods in FExxx?
func convert(fe lb.FE) *lb.SVC {
	switch fe := fe.(type) {
	case *lb.FENodePort:
		svc := &lb.SVC{}
		svc.Frontend.L4Addr = fe.L4Addr
		svc.Frontend.Scope = fe.Scope
		svc.TrafficPolicy = fe.TrafficPolicy
		svc.NatPolicy = fe.NatPolicy
		svc.SessionAffinity = fe.SessionAffinity
		svc.SessionAffinityTimeoutSec = fe.SessionAffinityTimeoutSec
		svc.HealthCheckNodePort = fe.HealthCheckNodePort
		return svc

	default:
		// Virtual frontend
		return nil
	}
}

// TODO: This and Frontend type should be defined by pkg/datapath/lb, e.g.
// it'd be the "datapath LoadBalancer entry" type.
// "LBService"?
type FrontAndBack struct {
	lb.Frontend
	Backends []*lb.Backend
}

func reduceFEs(name ServiceName, fes []lb.FE, serviceBackends []*lb.Backend) (out []*lb.SVC) {
	// Consider first virtual frontends that inherit the addresses of other frontends.
	// Local redirection goes first.
	redirs, fes := partition[*lb.FELocalRedirectService](fes)
	if len(redirs) > 0 {
		// TODO: what if many? maintain an invariant in upsert and reject duplicates?
		redir := redirs[0]
		svc := lb.SVC{
			Name: redir.Name,
			Type: lb.SVCTypeLocalRedirect,
			Backends: redir.Pods,
			TrafficPolicy: lb.SVCTrafficPolicyCluster,
		}
		for _, fe := range fes {
			addr := address(fe)
			if addr == nil { continue }
			svc := svc
			svc.Frontend.L3n4Addr = *addr
			out = append(out, &svc)
		}
		return
	}
	l7s, fes := partition[*lb.FEL7Proxy](fes)
	if len(l7s) > 0 {
		l7 := l7s[0]
		for _, fe := range fes {
			f, ok := convert(fe)
			if !ok { continue }
			f.L7LBProxyPort = l7.ProxyPort
			out = append(out,
			             FrontAndBack{
				             Frontend: f,
				             Backends: serviceBackends,
			             })
		}
		return
	}

	// TODO: resolve overlapping frontend addresses? Should UpsertFrontend already
	// reject them or should we just revolve them by priority and report per-frontend
	// status to the source (e.g. by updating Service.Status)?

	for _, fe := range fes {
		f, ok := convert(fe)
		if !ok { continue }
		out = append(out,
		             FrontAndBack{
			             Frontend: f,
			             Backends: serviceBackends,
		             })
	}


	return
}





*/
