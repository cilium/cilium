// Copyright 2016-2019 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package endpoint

import (
	"context"
	"fmt"
	"time"

	"github.com/cilium/cilium/pkg/controller"
	"github.com/cilium/cilium/pkg/endpoint/regeneration"
	"github.com/cilium/cilium/pkg/identity"
	pkgLabels "github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/option"

	"github.com/sirupsen/logrus"
)

// HasLabels returns whether endpoint e contains all labels l. Will return 'false'
// if any label in l is not in the endpoint's labels.
func (e *Endpoint) HasLabels(l pkgLabels.Labels) bool {
	e.unconditionalRLock()
	defer e.runlock()

	return e.hasLabelsRLocked(l)
}

// hasLabelsRLocked returns whether endpoint e contains all labels l. Will
// return 'false' if any label in l is not in the endpoint's labels.
// e.Mutex must be RLocked
func (e *Endpoint) hasLabelsRLocked(l pkgLabels.Labels) bool {
	allEpLabels := e.OpLabels.AllLabels()

	for _, v := range l {
		found := false
		for _, j := range allEpLabels {
			if j.Equals(&v) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	return true
}

// replaceInformationLabels replaces the information labels of the endpoint.
// Passing a nil set of labels will not perform any action.
// Must be called with e.Mutex.Lock().
func (e *Endpoint) replaceInformationLabels(l pkgLabels.Labels) {
	if l == nil {
		return
	}
	e.OpLabels.ReplaceInformationLabels(l, e.getLogger())
}

// replaceIdentityLabels replaces the identity labels of the endpoint. If a net
// changed occurred, the identityRevision is bumped and returned, otherwise 0 is
// returned.
// Passing a nil set of labels will not perform any action and will return the
// current endpoint's identityRevision.
// Must be called with e.Mutex.Lock().
func (e *Endpoint) replaceIdentityLabels(l pkgLabels.Labels) int {
	if l == nil {
		return e.identityRevision
	}

	changed := e.OpLabels.ReplaceIdentityLabels(l, e.getLogger())
	rev := 0
	if changed {
		e.identityRevision++
		rev = e.identityRevision
	}

	return rev
}

// ModifyIdentityLabels changes the custom and orchestration identity labels of an endpoint.
// Labels can be added or deleted. If a label change is performed, the
// endpoint will receive a new identity and will be regenerated. Both of these
// operations will happen in the background.
func (e *Endpoint) ModifyIdentityLabels(addLabels, delLabels pkgLabels.Labels) error {
	if err := e.lockAlive(); err != nil {
		return err
	}

	changed, err := e.OpLabels.ModifyIdentityLabels(addLabels, delLabels)
	if err != nil {
		e.unlock()
		return err
	}

	var rev int
	if changed {
		// Mark with StateWaitingForIdentity, it will be set to
		// StateWaitingToRegenerate after the identity resolution has been
		// completed
		e.setState(StateWaitingForIdentity, "Triggering identity resolution due to updated identity labels")

		e.identityRevision++
		rev = e.identityRevision
	}
	e.unlock()

	if changed {
		e.runLabelsResolver(context.Background(), rev, false)
	}
	return nil
}

// IsInit returns true if the endpoint still hasn't received identity labels,
// i.e. has the special identity with label reserved:init.
func (e *Endpoint) IsInit() bool {
	init, found := e.OpLabels.GetIdentityLabel(pkgLabels.IDNameInit)
	return found && init.Source == pkgLabels.LabelSourceReserved
}

// UpdateLabels is called to update the labels of an endpoint. Calls to this
// function do not necessarily mean that the labels actually changed. The
// container runtime layer will periodically synchronize labels.
//
// If a net label changed was performed, the endpoint will receive a new
// identity and will be regenerated. Both of these operations will happen in
// the background.
func (e *Endpoint) UpdateLabels(ctx context.Context, identityLabels, infoLabels pkgLabels.Labels, blocking bool) {
	log.WithFields(logrus.Fields{
		logfields.ContainerID:    e.GetShortContainerID(),
		logfields.EndpointID:     e.StringID(),
		logfields.IdentityLabels: identityLabels.String(),
		logfields.InfoLabels:     infoLabels.String(),
	}).Debug("Refreshing labels of endpoint")

	if err := e.lockAlive(); err != nil {
		e.logDisconnectedMutexAction(err, "when trying to refresh endpoint labels")
		return
	}

	e.replaceInformationLabels(infoLabels)
	// replace identity labels and update the identity if labels have changed
	rev := e.replaceIdentityLabels(identityLabels)
	e.unlock()
	if rev != 0 {
		e.runLabelsResolver(ctx, rev, blocking)
	}
}

func (e *Endpoint) identityResolutionIsObsolete(myChangeRev int) bool {
	// Check if the endpoint has since received a new identity revision, if
	// so, abort as a new resolution routine will have been started.
	if myChangeRev != e.identityRevision {
		return true
	}

	return false
}

// Must be called with e.Mutex NOT held.
func (e *Endpoint) runLabelsResolver(ctx context.Context, myChangeRev int, blocking bool) {
	if err := e.rlockAlive(); err != nil {
		// If a labels update and an endpoint delete API request arrive
		// in quick succession, this could occur; in that case, there's
		// no point updating the controller.
		e.getLogger().WithError(err).Info("Cannot run labels resolver")
		return
	}
	newLabels := e.OpLabels.IdentityLabels()
	e.runlock()
	scopedLog := e.getLogger().WithField(logfields.IdentityLabels, newLabels)

	// If we are certain we can resolve the identity without accessing the KV
	// store, do it first synchronously right now. This can reduce the number
	// of regenerations for the endpoint during its initialization.
	if blocking || identity.IdentityAllocationIsLocal(newLabels) {
		scopedLog.Info("Resolving identity labels (blocking)")

		err := e.identityLabelsChanged(ctx, myChangeRev)
		switch err {
		case ErrNotAlive:
			scopedLog.Debug("not changing endpoint identity because endpoint is in process of being removed")
			return
		default:
			if err != nil {
				scopedLog.WithError(err).Warn("Error changing endpoint identity")
			}
		}
	} else {
		scopedLog.Info("Resolving identity labels (non-blocking)")
	}

	ctrlName := fmt.Sprintf("resolve-identity-%d", e.ID)
	e.controllers.UpdateController(ctrlName,
		controller.ControllerParams{
			DoFunc: func(ctx context.Context) error {
				err := e.identityLabelsChanged(ctx, myChangeRev)
				switch err {
				case ErrNotAlive:
					e.getLogger().Debug("not changing endpoint identity because endpoint is in process of being removed")
					return controller.NewExitReason("Endpoint disappeared")
				default:
					return err
				}
			},
			RunInterval: 5 * time.Minute,
		},
	)
}

func (e *Endpoint) identityLabelsChanged(ctx context.Context, myChangeRev int) error {
	if err := e.rlockAlive(); err != nil {
		return ErrNotAlive
	}
	newLabels := e.OpLabels.IdentityLabels()
	elog := e.getLogger().WithFields(logrus.Fields{
		logfields.EndpointID:     e.ID,
		logfields.IdentityLabels: newLabels,
	})

	// Since we unlocked the endpoint and re-locked, the label update may already be obsolete
	if e.identityResolutionIsObsolete(myChangeRev) {
		e.runlock()
		elog.Debug("Endpoint identity has changed, aborting resolution routine in favour of new one")
		return nil
	}

	if e.SecurityIdentity != nil && e.SecurityIdentity.Labels.Equals(newLabels) {
		// Sets endpoint state to ready if was waiting for identity
		if e.getState() == StateWaitingForIdentity {
			e.setState(StateReady, "Set identity for this endpoint")
		}
		e.runlock()
		elog.Debug("Endpoint labels unchanged, skipping resolution of identity")
		return nil
	}

	// Unlock the endpoint mutex for the possibly long lasting kvstore operation
	e.runlock()
	elog.Debug("Resolving identity for labels")

	allocateCtx, cancel := context.WithTimeout(context.Background(), option.Config.KVstoreConnectivityTimeout)
	defer cancel()

	allocatedIdentity, _, err := e.allocator.AllocateIdentity(allocateCtx, newLabels, true)
	if err != nil {
		err = fmt.Errorf("unable to resolve identity: %s", err)
		e.LogStatus(Other, Warning, fmt.Sprintf("%s (will retry)", err.Error()))
		return err
	}

	// When releasing identities after allocation due to either failure of
	// allocation or due a no longer used identity we want to operation to
	// continue even if the parent has given up. Enforce a timeout of two
	// minutes to avoid blocking forever but give plenty of time to release
	// the identity.
	releaseCtx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	releaseNewlyAllocatedIdentity := func() {
		_, err := e.allocator.Release(releaseCtx, allocatedIdentity)
		if err != nil {
			// non fatal error as keys will expire after lease expires but log it
			elog.WithFields(logrus.Fields{logfields.Identity: allocatedIdentity.ID}).
				WithError(err).Warn("Unable to release newly allocated identity again")
		}
	}

	if err := e.lockAlive(); err != nil {
		releaseNewlyAllocatedIdentity()
		return err
	}

	// Since we unlocked the endpoint and re-locked, the label update may already be obsolete
	if e.identityResolutionIsObsolete(myChangeRev) {
		e.unlock()

		releaseNewlyAllocatedIdentity()

		return nil
	}

	// If endpoint has an old identity, defer release of it to the end of
	// the function after the endpoint structured has been unlocked again
	oldIdentity := e.SecurityIdentity
	if oldIdentity != nil {
		// The identity of the endpoint is changing, delay the use of
		// the identity by a grace period to give all other cluster
		// nodes a chance to adjust their policies first. This requires
		// to unlock the endpoit and then lock it again.
		//
		// If the identity change is from init -> *, don't delay the
		// use of the identity as we want the init duration to be as
		// short as possible.
		if allocatedIdentity.ID != oldIdentity.ID && oldIdentity.ID != identity.ReservedIdentityInit {
			e.unlock()

			elog.Debugf("Applying grace period before regeneration due to identity change")
			time.Sleep(option.Config.IdentityChangeGracePeriod)

			if err := e.lockAlive(); err != nil {
				releaseNewlyAllocatedIdentity()
				return err
			}

			// Since we unlocked the endpoint and re-locked, the label update may already be obsolete
			if e.identityResolutionIsObsolete(myChangeRev) {
				e.unlock()
				releaseNewlyAllocatedIdentity()
				return nil
			}
		}
	}

	elog.WithFields(logrus.Fields{logfields.Identity: allocatedIdentity.StringID()}).
		Debug("Assigned new identity to endpoint")

	e.SetIdentity(allocatedIdentity, false)

	if oldIdentity != nil {
		_, err := e.allocator.Release(releaseCtx, oldIdentity)
		if err != nil {
			elog.WithFields(logrus.Fields{logfields.Identity: oldIdentity.ID}).
				WithError(err).Warn("Unable to release old endpoint identity")
		}
	}

	readyToRegenerate := false

	// Regeneration is only triggered once the endpoint ID has been
	// assigned. This ensures that on the initial creation, the endpoint is
	// not generated until the endpoint ID has been assigned. If the
	// identity is resolved before the endpoint ID is assigned, the
	// regeneration is deferred into endpointmanager.AddEndpoint(). If the
	// identity is not allocated yet when endpointmanager.AddEndpoint() is
	// called, the controller calling identityLabelsChanged() will trigger
	// the regeneration as soon as the identity is known.
	if e.ID != 0 {
		readyToRegenerate = e.setState(StateWaitingToRegenerate, "Triggering regeneration due to new identity")
	}

	// Unconditionally force policy recomputation after a new identity has been
	// assigned.
	e.forcePolicyComputation()

	e.unlock()

	if readyToRegenerate {
		e.Regenerate(&regeneration.ExternalRegenerationMetadata{Reason: "updated security labels"})
	}

	return nil
}
