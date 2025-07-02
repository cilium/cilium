// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package testcompute

import (
	"context"
	"log/slog"
	"testing"

	"github.com/cilium/hive/cell"
	"github.com/cilium/statedb"
	"github.com/cilium/stream"

	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/identity/identitymanager"
	"github.com/cilium/cilium/pkg/policy"
	policycompute "github.com/cilium/cilium/pkg/policy/compute"
)

func InstantiateCellForTesting(tb testing.TB, logger *slog.Logger, id, desc string, repo policy.PolicyRepository, idmgr identitymanager.IDManager) policycompute.PolicyRecomputer {
	tb.Helper()

	var pc policycompute.PolicyRecomputer

	h := hive.New(
		cell.Module(id, desc,
			cell.Invoke(
				func(c_ policycompute.PolicyRecomputer) error {
					pc = c_
					return nil
				},
			),

			cell.ProvidePrivate(func() (policy.PolicyRepository, stream.Observable[policy.PolicyCacheChange]) {
				return repo, repo.PolicyCacheObservable()
			}),
			cell.ProvidePrivate(func() identitymanager.IDManager { return idmgr }),

			cell.Provide(
				func(params policycompute.Params) policycompute.PolicyRecomputer {
					return policycompute.NewIdentityPolicyComputer(params)
				},
			),
			cell.Provide(policycompute.NewPolicyComputationTable),
			cell.Provide(statedb.RWTable[policycompute.Result].ToTable),
		),
	)

	if err := h.Start(logger, context.Background()); err != nil {
		tb.Fatalf("failed to start hive: %v", err)
	}
	tb.Cleanup(func() {
		if err := h.Stop(logger, context.Background()); err != nil {
			tb.Fatalf("failed to stop hive: %v", err)
		}
	})

	return pc
}
