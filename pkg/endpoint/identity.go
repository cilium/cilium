// Copyright 2016-2018 Authors of Cilium
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
	"github.com/cilium/cilium/pkg/controller"

	identityPkg "github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/sirupsen/logrus"
	"time"
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
