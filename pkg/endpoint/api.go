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
	"bytes"

	"github.com/cilium/cilium/api/v1/models"
)

// GetLabelsModel returns the labels of the endpoint in their representation
// for the Cilium API. Returns an error if the Endpoint is being deleted.
func (e *Endpoint) GetLabelsModel() (*models.LabelConfiguration, error) {
	if err := e.RLockAlive(); err != nil {
		return nil, err
	}
	spec := &models.LabelConfigurationSpec{
		User: e.OpLabels.Custom.GetModel(),
	}

	cfg := models.LabelConfiguration{
		Spec: spec,
		Status: &models.LabelConfigurationStatus{
			Realized:         spec,
			SecurityRelevant: e.OpLabels.OrchestrationIdentity.GetModel(),
			Derived:          e.OpLabels.OrchestrationInfo.GetModel(),
			Disabled:         e.OpLabels.Disabled.GetModel(),
		},
	}
	e.RUnlock()
	return &cfg, nil
}

func ValidPatchTransitionState(state models.EndpointState) bool {
	switch string(state) {
	case "", StateWaitingForIdentity, StateReady:
		return true
	}
	return false
}

// ProcessChangeRequest handles the update logic for performing a PATCH operation
// on a given Endpoint. Returns the reason which will be used for informational
// purposes should a caller choose to try to regenerate this endpoint, as well
// as an error if the Endpoint is being deleted, since there is no point in
// changing an Endpoint if it is going to be deleted.
func (e *Endpoint) ProcessChangeRequest(epTemplate *models.EndpointChangeRequest, newEp *Endpoint) (string, error) {
	var (
		changed bool
		reason  string
	)

	if err := e.LockAlive(); err != nil {
		return "", err
	}
	defer e.Unlock()

	if epTemplate.InterfaceIndex != 0 && e.IfIndex != newEp.IfIndex {
		e.IfIndex = newEp.IfIndex
		changed = true
	}

	if epTemplate.InterfaceName != "" && e.IfName != newEp.IfName {
		e.IfName = newEp.IfName
		changed = true
	}

	// Only support transition to waiting-for-identity state, also
	// if the request is for ready state, as we will check the
	// existence of the security label below. Other transitions
	// are always internally managed, but we do not error out for
	// backwards compatibility.
	if epTemplate.State != "" &&
		ValidPatchTransitionState(epTemplate.State) &&
		e.GetStateLocked() != StateWaitingForIdentity {
		// Will not change state if the current state does not allow the transition.
		if e.SetStateLocked(StateWaitingForIdentity, "Update endpoint from API PATCH") {
			changed = true
		}
	}

	if epTemplate.Mac != "" && bytes.Compare(e.LXCMAC, newEp.LXCMAC) != 0 {
		e.LXCMAC = newEp.LXCMAC
		changed = true
	}

	if epTemplate.HostMac != "" && bytes.Compare(e.GetNodeMAC(), newEp.NodeMAC) != 0 {
		e.SetNodeMACLocked(newEp.NodeMAC)
		changed = true
	}

	if epTemplate.Addressing != nil {
		if ip := epTemplate.Addressing.IPV6; ip != "" && bytes.Compare(e.IPv6, newEp.IPv6) != 0 {
			e.IPv6 = newEp.IPv6
			changed = true
		}

		if ip := epTemplate.Addressing.IPV4; ip != "" && bytes.Compare(e.IPv4, newEp.IPv4) != 0 {
			e.IPv4 = newEp.IPv4
			changed = true
		}
	}

	// TODO: Do something with the labels?
	// addLabels := labels.NewLabelsFromModel(params.Endpoint.Labels)

	// If desired state is waiting-for-identity but identity is already
	// known, bump it to ready state immediately to force re-generation
	if e.GetStateLocked() == StateWaitingForIdentity && e.SecurityIdentity != nil {
		e.SetStateLocked(StateReady, "Preparing to force endpoint regeneration because identity is known while handling API PATCH")
		changed = true
	}

	if changed {
		// Force policy regeneration as endpoint's configuration was changed.
		// Other endpoints need not be regenerated as no labels were changed.
		// Note that we still need to (eventually) regenerate the endpoint for
		// the changes to take effect.
		e.ForcePolicyCompute()

		// Transition to waiting-to-regenerate if ready.
		if e.GetStateLocked() == StateReady {
			e.SetStateLocked(StateWaitingToRegenerate, "Forcing endpoint regeneration because identity is known while handling API PATCH")
		}

		switch e.GetStateLocked() {
		case StateWaitingToRegenerate:
			reason = "Waiting on endpoint regeneration because identity is known while handling API PATCH"
		case StateWaitingForIdentity:
			reason = "Waiting on endpoint initial program regeneration while handling API PATCH"
		}
	}

	e.UpdateLogger(nil)

	return reason, nil
}
