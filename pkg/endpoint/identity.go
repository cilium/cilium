// Copyright 2018 Authors of Cilium
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
	"fmt"
	"time"

	"github.com/cilium/cilium/pkg/controller"
	identityPkg "github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/logging/logfields"

	"github.com/sirupsen/logrus"
)

func (e *Endpoint) identityResolutionIsObsolete(myChangeRev int) bool {
	// If in disconnected state, skip as well as this operation is no
	// longer required.
	if e.state == StateDisconnected {
		return true
	}

	// Check if the endpoint has since received a new identity revision, if
	// so, abort as a new resolution routine will have been started.
	if myChangeRev != e.identityRevision {
		return true
	}

	return false
}

func (e *Endpoint) runLabelsResolver(owner Owner, myChangeRev int) {
	ctrlName := fmt.Sprintf("resolve-identity-%d", e.ID)
	e.controllers.UpdateController(ctrlName,
		controller.ControllerParams{
			DoFunc: func() error {
				return e.identityLabelsChanged(owner, myChangeRev)
			},
			RunInterval: time.Duration(5) * time.Minute,
		},
	)
}

func (e *Endpoint) identityLabelsChanged(owner Owner, myChangeRev int) error {
	e.Mutex.RLock()
	newLabels := e.OpLabels.IdentityLabels()
	elog := log.WithFields(logrus.Fields{
		logfields.EndpointID:     e.ID,
		logfields.IdentityLabels: newLabels,
	})

	// Since we unlocked the endpoint and re-locked, the label update may already be obsolete
	if e.identityResolutionIsObsolete(myChangeRev) {
		e.Mutex.RUnlock()
		elog.Debug("Endpoint identity has changed, aborting resolution routine in favour of new one")
		return nil
	}

	if e.SecurityIdentity != nil &&
		string(e.SecurityIdentity.Labels.SortedList()) == string(newLabels.SortedList()) {

		e.Mutex.RUnlock()
		elog.Debug("Endpoint labels unchanged, skipping resolution of identity")
		return nil
	}

	// Unlock the endpoint mutex for the possibly long lasting kvstore operation
	e.Mutex.RUnlock()
	elog.Debug("Resolving identity for labels")

	identity, _, err := identityPkg.AllocateIdentity(newLabels)
	if err != nil {
		err = fmt.Errorf("unable to resolve identity: %s", err)
		e.LogStatus(Other, Warning, fmt.Sprintf("%s (will retry)", err.Error()))
		return err
	}

	e.Mutex.Lock()

	// Since we unlocked the endpoint and re-locked, the label update may already be obsolete
	if e.identityResolutionIsObsolete(myChangeRev) {
		e.Mutex.Unlock()

		err := identity.Release()
		if err != nil {
			// non fatal error as keys will expire after lease expires but log it
			elog.WithFields(logrus.Fields{logfields.Identity: identity.ID}).
				WithError(err).Warn("Unable to release newly allocated identity again")
		}

		return nil
	}

	// If endpoint has an old identity, defer release of it to the end of
	// the function after the endpoint structured has been unlocked again
	if e.SecurityIdentity != nil {
		oldIdentity := e.SecurityIdentity
		defer func() {
			err := oldIdentity.Release()
			if err != nil {
				elog.WithFields(logrus.Fields{logfields.Identity: oldIdentity.ID}).
					WithError(err).Warn("BUG: Unable to release old endpoint identity")
			}
		}()
	}

	elog.WithFields(logrus.Fields{logfields.Identity: identity.StringID()}).
		Debug("Assigned new identity to endpoint")

	e.SetIdentity(identity)

	ready := e.SetStateLocked(StateWaitingToRegenerate, "Triggering regeneration due to new identity")
	if ready {
		e.ForcePolicyCompute()
	}

	e.Mutex.Unlock()

	if ready {
		e.Regenerate(owner, "updated security labels")
	}

	return nil
}

// ModifyIdentityLabels changes the identity relevant labels of an endpoint.
// labels can be added or deleted. If a net label changed is performed, the
// endpoint will receive a new identity and will be regenerated. Both of these
// operations will happen in the background.
func (e *Endpoint) ModifyIdentityLabels(owner Owner, addLabels, delLabels labels.Labels) error {
	e.Mutex.Lock()
	defer e.Mutex.Unlock()

	newLabels := e.OpLabels.DeepCopy()

	if len(delLabels) > 0 {
		for k := range delLabels {
			// The change request is accepted if the label is on
			// any of the lists. If the label is already disabled,
			// we will simply ignore that change.
			if newLabels.OrchestrationIdentity[k] != nil ||
				newLabels.Custom[k] != nil ||
				newLabels.Disabled[k] != nil {
				break
			}

			return fmt.Errorf("label %s not found", k)
		}
	}

	if len(delLabels) > 0 {
		for k, v := range delLabels {
			if newLabels.OrchestrationIdentity[k] != nil {
				delete(newLabels.OrchestrationIdentity, k)
				newLabels.Disabled[k] = v
			}

			if newLabels.Custom[k] != nil {
				delete(newLabels.Custom, k)
			}
		}
	}

	if len(addLabels) > 0 {
		for k, v := range addLabels {
			if newLabels.Disabled[k] != nil {
				delete(newLabels.Disabled, k)
				newLabels.OrchestrationIdentity[k] = v
			} else if newLabels.OrchestrationIdentity[k] == nil {
				newLabels.Custom[k] = v
			}
		}
	}

	e.OpLabels = *newLabels

	// Mark with StateWaitingForIdentity, it will be set to
	// StateWaitingToRegenerate after the identity resolution has been
	// completed
	e.SetStateLocked(StateWaitingForIdentity, "Triggering identity resolution due to updated security labels")

	e.identityRevision++
	rev := e.identityRevision

	e.runLabelsResolver(owner, rev)

	return nil
}
