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
	pkgLabels "github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/sirupsen/logrus"
)

// HasLabels returns whether endpoint e contains all labels l. Will return 'false'
// if any label in l is not in the endpoint's labels.
func (e *Endpoint) HasLabels(l pkgLabels.Labels) bool {
	e.Mutex.RLock()
	defer e.Mutex.RUnlock()
	allEpLabels := e.OpLabels.AllLabels()

	for _, v := range l {
		found := false
		for _, j := range allEpLabels {
			if j.Equals(v) {
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

func (e *Endpoint) replaceInformationLabels(l pkgLabels.Labels) {
	e.Mutex.Lock()
	for k, v := range l {
		tmp := v.DeepCopy()
		e.getLogger().WithField(logfields.Labels, logfields.Repr(tmp)).Debug("Assigning orchestration information label")
		e.OpLabels.OrchestrationInfo[k] = tmp
	}
	e.Mutex.Unlock()
}

// replaceIdentityLabels replaces the identity labels of an endpoint. If a net
// changed occurred, the identityRevision is bumped and return, otherwise 0 is
// returned.
func (e *Endpoint) replaceIdentityLabels(l pkgLabels.Labels) int {
	e.Mutex.Lock()
	changed := false

	e.OpLabels.OrchestrationIdentity.MarkAllForDeletion()
	e.OpLabels.Disabled.MarkAllForDeletion()

	for k, v := range l {
		switch {
		case e.OpLabels.Disabled[k] != nil:
			e.OpLabels.Disabled[k].DeletionMark = false

		case e.OpLabels.OrchestrationIdentity[k] != nil:
			e.OpLabels.OrchestrationIdentity[k].DeletionMark = false

		default:
			tmp := v.DeepCopy()
			e.getLogger().WithField(logfields.Labels, logfields.Repr(tmp)).Debug("Assigning orchestration identity label")
			e.OpLabels.OrchestrationIdentity[k] = tmp
			changed = true
		}
	}

	if e.OpLabels.OrchestrationIdentity.DeleteMarked() || e.OpLabels.Disabled.DeleteMarked() {
		changed = true
	}

	rev := 0
	if changed {
		e.identityRevision++
		rev = e.identityRevision
	}

	e.Mutex.Unlock()

	return rev
}

// UpdateLabels is called to update the labels of an endpoint. Calls to this
// function do not necessarily mean that the labels actually changed. The
// container runtime layer will periodically synchronize labels.
//
// If a net label changed was performed, the endpoint will receive a new
// identity and will be regenerated. Both of these operations will happen in
// the background.
func (e *Endpoint) UpdateLabels(owner Owner, identityLabels, infoLabels pkgLabels.Labels) {
	log.WithFields(logrus.Fields{
		logfields.ContainerID:    e.GetShortContainerID(),
		logfields.EndpointID:     e.StringID(),
		logfields.IdentityLabels: identityLabels.String(),
		logfields.InfoLabels:     infoLabels.String(),
	}).Debug("Refreshing labels of endpoint")

	e.replaceInformationLabels(infoLabels)

	// replace identity labels and update the identity if labels have changed
	if rev := e.replaceIdentityLabels(identityLabels); rev != 0 {
		e.runLabelsResolver(owner, rev)
	}
}
