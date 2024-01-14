package health

import (
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/hive/cell"
)

type reporterHooks struct {
	rootScope *scope
}

func (r *reporterHooks) Start(ctx hive.HookContext) error {
	return nil
}

func (r *reporterHooks) Stop(ctx hive.HookContext) error {
	return nil
}

func createStructedScope(id cell.FullModuleID, p Health, lc hive.Lifecycle) (Scope, error) {
	s, err := p.forModule(id)
	if err != nil {
		return nil, err
	}
	rs := rootScope(id, s)
	lc.Append(&reporterHooks{rootScope: rs})
	return rs, nil
}

type healthScopeParams struct {
	cell.In

	FullModuleID cell.FullModuleID
	Health       Health
	Lifecycle    hive.Lifecycle

	Scope Scope `optional:"true"` // injected as optional, if one already exists then we derive
	// from that one, otherwise we create a new one.
}

type initRootParams struct {
	cell.In

	FullModuleID cell.FullModuleID
	Health       Health
	Lifecycle    hive.Lifecycle
}

var Cell = cell.Provide(func(p initRootParams) (Scope, error) {
	return createStructedScope(p.FullModuleID, p.Health, p.Lifecycle)
})

func ProvideHealthScope() cell.Cell {
	// So what's happening here, is that we actually have a health reporter bring provided globally.
	//
	// This is a bit scary, since the structure reporter is now a global singleton, but the next step
	// is to use a immutable, radix-based, data structure to store the health information so that would
	// actually be fine.
	//
	// Maybe, as a proof-of-concept, lets just use StateDB to store the health information and I can
	// work with Jussi to figure out any circular dependency type issues that might arise later.
	//
	// We provide private, so that we can only access down the tree.
	// This will likely crash if add more of these, so we should probably use a decorator pattern.
	// return cell.ProvidePrivate(func(id cell.FullModuleID, p Health, lc hive.Lifecycle) Scope {
	// 	return createStructedScope(id, p, lc)
	// })

	// TODO: Decorate private?
	return cell.Decorate(func(p healthScopeParams) Scope {
		// if p.Scope == nil {
		// 	return createStructedScope(p.FullModuleID, p.Health, p.Lifecycle)
		// } else {
		// 	return GetSubScope(p.Scope, p.FullModuleID.String())
		// }
		return GetSubScope(p.Scope, p.FullModuleID.String())
	})
	// Idea: we could try a an "optional" decorator pattern:
}
