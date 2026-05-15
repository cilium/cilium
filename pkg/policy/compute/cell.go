// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package compute

import (
	"context"
	"log/slog"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/cilium/statedb"

	"github.com/cilium/cilium/pkg/identity/identitymanager"
	"github.com/cilium/cilium/pkg/lock"
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

		trigger: make(chan struct{}, 1),
	}

	// Subscribe directly to identitymanager. Observer callbacks fire
	// synchronously under idm.mutex, so they must remain non-blocking. See
	// the receiver methods for the constraint.
	params.IDManager.Subscribe(obj)

	params.JobGroup.Add(
		job.OneShot("policy-computation-loop", func(ctx context.Context, health cell.Health) error {
			return obj.processRequests(ctx)
		}),
	)
	return obj
}

// IdentityPolicyComputer handles policy computation for specific identities.
type IdentityPolicyComputer struct {
	logger *slog.Logger

	db  *statedb.DB
	tbl statedb.RWTable[Result]

	repo      policy.PolicyRepository
	idmanager identitymanager.IDManager

	reqsMu  lock.Mutex
	reqs    []computeRequest
	trigger chan struct{}
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
}
