// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package compute

import (
	"log/slog"

	"github.com/cilium/hive/cell"
	"github.com/cilium/statedb"

	"github.com/cilium/cilium/pkg/identity/identitymanager"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/policy"
)

// Cell provides the IdentityPolicyRecomputer as a hive cell.
var Cell = cell.Module(
	"identity-policy-recomputer",
	"Handles policy recomputation for specific identities",

	cell.ProvidePrivate(newTable),
	cell.Provide(
		func(params Params) PolicyRecomputer {
			return NewIdentityPolicyRecomputer(params)
		},
		statedb.RWTable[Result].ToTable,
	),
)

func NewIdentityPolicyRecomputer(params Params) *IdentityPolicyRecomputer {
	obj := &IdentityPolicyRecomputer{
		db:  params.DB,
		tbl: params.Table,

		repo:      params.Repo,
		idmanager: params.IDManager,
		logger:    params.Logger,
	}

	params.Lifecycle.Append(cell.Hook{
		OnStart: func(cell.HookContext) error {
			params.Logger.Info("Identity policy recomputer started")
			params.IDManager.Subscribe(obj)
			return nil
		},
		OnStop: func(cell.HookContext) error {
			params.Logger.Info("Identity policy recomputer stopped")
			return nil
		},
	})
	return obj
}

// IdentityPolicyRecomputer handles policy recomputation for specific identities.
type IdentityPolicyRecomputer struct {
	mu lock.RWMutex

	logger *slog.Logger

	db  *statedb.DB
	tbl statedb.RWTable[Result]

	repo      policy.PolicyRepository
	idmanager identitymanager.IDManager
}

type Params struct {
	cell.In

	Lifecycle cell.Lifecycle
	Logger    *slog.Logger

	DB    *statedb.DB
	Table statedb.RWTable[Result]

	Repo      policy.PolicyRepository
	IDManager identitymanager.IDManager
}
