// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package compute

import (
	"log/slog"
	"testing"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/cilium/statedb"
	"github.com/cilium/stream"

	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/identity/identitymanager"
	"github.com/cilium/cilium/pkg/policy"
)

// Cell provides the IdentityPolicyRecomputer as a hive cell.
var Cell = cell.Module(
	"identity-policy-computer",
	"Handles policy computation per identity",

	cell.ProvidePrivate(NewPolicyComputationTable),
	cell.Provide(
		func(params Params) PolicyRecomputer {
			return NewIdentityPolicyComputer(params)
		},
		statedb.RWTable[Result].ToTable,
	),
)

func NewIdentityPolicyComputer(params Params) *IdentityPolicyComputer {
	obj := &IdentityPolicyComputer{
		db:  params.DB,
		tbl: params.Table,

		repo:      params.Repo,
		idmanager: params.IDManager,

		logger: params.Logger,

		policyCacheEvents: params.PolicyCacheEvents,
	}

	params.Lifecycle.Append(cell.Hook{
		OnStart: func(cell.HookContext) error {
			params.JobGroup.Add(
				job.Observer[policy.PolicyCacheChange](
					"policy-cache-observer",
					obj.handlePolicyCacheEvent,
					obj.policyCacheEvents,
				),
			)
			return nil
		},
		OnStop: func(cell.HookContext) error { return nil },
	})
	return obj
}

// IdentityPolicyComputer handles policy computation for specific identities.
type IdentityPolicyComputer struct {
	logger *slog.Logger

	db  *statedb.DB
	tbl statedb.RWTable[Result]

	repo      policy.PolicyRepository
	idmanager identitymanager.IDManager

	policyCacheEvents stream.Observable[policy.PolicyCacheChange]
}

type Params struct {
	cell.In

	Lifecycle cell.Lifecycle
	Logger    *slog.Logger
	JobGroup  job.Group

	DB    *statedb.DB
	Table statedb.RWTable[Result]

	Repo      policy.PolicyRepository
	IDManager identitymanager.IDManager

	PolicyCacheEvents stream.Observable[policy.PolicyCacheChange]
}

func InstantiateCellForTesting(tb testing.TB, logger *slog.Logger, id, desc string, repo policy.PolicyRepository, idmgr identitymanager.IDManager) PolicyRecomputer {
	tb.Helper()

	var pc PolicyRecomputer

	hive.New(
		cell.Module(id, desc,
			cell.Invoke(
				func(c_ PolicyRecomputer) error {
					pc = c_
					return nil
				},
			),

			cell.ProvidePrivate(func() (policy.PolicyRepository, stream.Observable[policy.PolicyCacheChange]) {
				return repo, repo.PolicyCacheObservable()
			}),
			cell.ProvidePrivate(func() identitymanager.IDManager { return idmgr }),

			cell.Provide(
				func(params Params) PolicyRecomputer {
					return NewIdentityPolicyComputer(params)
				},
			),
			cell.Provide(NewPolicyComputationTable),
			cell.Provide(statedb.RWTable[Result].ToTable),
		),
	).Populate(logger)

	return pc
}
