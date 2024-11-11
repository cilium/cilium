// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package policy

import (
	"github.com/cilium/cilium/pkg/logging/logfields"
)

// TriggerPolicyUpdates force full policy recomputation before
// regenerating all endpoints.
// This artificially bumps the policy revision, invalidating
// all cached policies. This is done when an additional resource
// used in policy calculation has changed.
func (u *Updater) TriggerPolicyUpdates(reason string) {
	u.repo.BumpRevision()
	log.WithField(logfields.Reason, reason).Info("Triggering full policy recalculation and regeneration of all endpoints")
	u.regen.TriggerRegenerateAllEndpoints()
}

// NewUpdater returns a new Updater instance to handle triggering policy
// updates ready for use.
func NewUpdater(r PolicyRepository, regen regenerator) *Updater {
	return &Updater{
		regen: regen,
		repo:  r,
	}
}

// Updater is responsible for triggering policy updates, in order to perform
// policy recalculation.
type Updater struct {
	repo  PolicyRepository
	regen regenerator
}

type regenerator interface {
	// RegenerateAllEndpoints should trigger a regeneration of all endpoints.
	TriggerRegenerateAllEndpoints()
}
