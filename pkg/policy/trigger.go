// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package policy

import (
	"log/slog"

	"github.com/cilium/statedb"

	"github.com/cilium/cilium/pkg/logging/logfields"
)

// TriggerPolicyUpdates force full policy recomputation before
// regenerating all endpoints.
// This artificially bumps the policy revision, invalidating
// all cached policies. This is done when an additional resource
// used in policy calculation has changed.
func (u *Updater) TriggerPolicyUpdates(reason string) {
	rev := u.repo.BumpRevision()
	u.computer.RecomputeIdentityPolicyForAllIdentities(rev)
	u.logger.Info("Triggering full policy recalculation and regeneration of all endpoints", logfields.Reason, reason)
	u.regen.RegenerateAllForPolicy(rev)
}

// NewUpdater returns a new Updater instance to handle triggering policy
// updates ready for use.
func NewUpdater(logger *slog.Logger, r PolicyRepository, c computer, regen regenerator) *Updater {
	return &Updater{
		logger:   logger,
		regen:    regen,
		repo:     r,
		computer: c,
	}
}

// Updater is responsible for triggering policy updates, in order to perform
// policy recalculation.
type Updater struct {
	logger   *slog.Logger
	repo     PolicyRepository
	computer computer
	regen    regenerator
}

type regenerator interface {
	// RegenerateAllForPolicy triggers regeneration of all endpoints against
	// the given policy revision. See endpointmanager.EndpointManager.
	RegenerateAllForPolicy(waitFor uint64)
}

type computer interface {
	RecomputeIdentityPolicyForAllIdentities(toRev uint64) (*statedb.WatchSet, error)
}
