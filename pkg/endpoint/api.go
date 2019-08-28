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

// This file contains functions related to conversion of information about
// an Endpoint to its corresponding Cilium API representation.

package endpoint

import (
	"bytes"
	"sort"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/common/addressing"
	"github.com/cilium/cilium/pkg/controller"
	"github.com/cilium/cilium/pkg/endpoint/regeneration"
	"github.com/cilium/cilium/pkg/fqdn"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/labels/model"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/mac"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/policy/trafficdirection"
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

// NewEndpointFromChangeModel creates a new endpoint from a request
func NewEndpointFromChangeModel(owner regeneration.Owner, base *models.EndpointChangeRequest) (*Endpoint, error) {
	if base == nil {
		return nil, nil
	}

	ep := &Endpoint{
		owner:            owner,
		ID:               uint16(base.ID),
		ContainerName:    base.ContainerName,
		ContainerID:      base.ContainerID,
		DockerNetworkID:  base.DockerNetworkID,
		DockerEndpointID: base.DockerEndpointID,
		ifName:           base.InterfaceName,
		K8sPodName:       base.K8sPodName,
		K8sNamespace:     base.K8sNamespace,
		datapathMapID:    int(base.DatapathMapID),
		ifIndex:          int(base.InterfaceIndex),
		OpLabels:         labels.NewOpLabels(),
		DNSHistory:       fqdn.NewDNSCacheWithLimit(option.Config.ToFQDNsMinTTL, option.Config.ToFQDNsMaxIPsPerHost),
		state:            "",
		status:           NewEndpointStatus(),
		hasBPFProgram:    make(chan struct{}, 0),
		desiredPolicy:    policy.NewEndpointPolicy(owner.GetPolicyRepository()),
		controllers:      controller.NewManager(),
	}
	ep.realizedPolicy = ep.desiredPolicy

	if base.Mac != "" {
		m, err := mac.ParseMAC(base.Mac)
		if err != nil {
			return nil, err
		}
		ep.mac = m
	}

	if base.HostMac != "" {
		m, err := mac.ParseMAC(base.HostMac)
		if err != nil {
			return nil, err
		}
		ep.nodeMAC = m
	}

	if base.Addressing != nil {
		if ip := base.Addressing.IPV6; ip != "" {
			ip6, err := addressing.NewCiliumIPv6(ip)
			if err != nil {
				return nil, err
			}
			ep.IPv6 = ip6
		}

		if ip := base.Addressing.IPV4; ip != "" {
			ip4, err := addressing.NewCiliumIPv4(ip)
			if err != nil {
				return nil, err
			}
			ep.IPv4 = ip4
		}
	}

	if base.DatapathConfiguration != nil {
		ep.DatapathConfiguration = *base.DatapathConfiguration
	}

	ep.SetDefaultOpts(option.Config.Opts)

	ep.UpdateLogger(nil)
	ep.SetStateLocked(string(base.State), "Endpoint creation")

	return ep, nil
}

// GetModelRLocked returns the API model of endpoint e.
// e.mutex must be RLocked.
func (e *Endpoint) GetModelRLocked() *models.Endpoint {
	if e == nil {
		return nil
	}

	currentState := models.EndpointState(e.state)
	if currentState == models.EndpointStateReady && e.status.CurrentStatus() != OK {
		currentState = models.EndpointStateNotReady
	}

	// This returns the most recent log entry for this endpoint. It is backwards
	// compatible with the json from before we added `cilium endpoint log` but it
	// only returns 1 entry.
	statusLog := e.status.GetModel()
	if len(statusLog) > 0 {
		statusLog = statusLog[:1]
	}

	lblMdl := model.NewModel(&e.OpLabels)

	// Sort these slices since they come out in random orders. This allows
	// reflect.DeepEqual to succeed.
	sort.StringSlice(lblMdl.Realized.User).Sort()
	sort.StringSlice(lblMdl.Disabled).Sort()
	sort.StringSlice(lblMdl.SecurityRelevant).Sort()
	sort.StringSlice(lblMdl.Derived).Sort()

	controllerMdl := e.controllers.GetStatusModel()
	sort.Slice(controllerMdl, func(i, j int) bool { return controllerMdl[i].Name < controllerMdl[j].Name })

	spec := &models.EndpointConfigurationSpec{
		LabelConfiguration: lblMdl.Realized,
	}

	if e.Options != nil {
		spec.Options = *e.Options.GetMutableModel()
	}

	mdl := &models.Endpoint{
		ID:   int64(e.ID),
		Spec: spec,
		Status: &models.EndpointStatus{
			// FIXME GH-3280 When we begin implementing revision numbers this will
			// diverge from models.Endpoint.Spec to reflect the in-datapath config
			Realized: spec,
			Identity: e.SecurityIdentity.GetModel(),
			Labels:   lblMdl,
			Networking: &models.EndpointNetworking{
				Addressing: []*models.AddressPair{{
					IPV4: e.IPv4.String(),
					IPV6: e.IPv6.String(),
				}},
				InterfaceIndex: int64(e.ifIndex),
				InterfaceName:  e.ifName,
				Mac:            e.mac.String(),
				HostMac:        e.nodeMAC.String(),
			},
			ExternalIdentifiers: &models.EndpointIdentifiers{
				ContainerID:      e.ContainerID,
				ContainerName:    e.ContainerName,
				DockerEndpointID: e.DockerEndpointID,
				DockerNetworkID:  e.DockerNetworkID,
				PodName:          e.GetK8sNamespaceAndPodNameLocked(),
			},
			// FIXME GH-3280 When we begin returning endpoint revisions this should
			// change to return the configured and in-datapath policies.
			Policy:      e.GetPolicyModel(),
			Log:         statusLog,
			Controllers: controllerMdl,
			State:       currentState, // TODO: Validate
			Health:      e.getHealthModel(),
		},
	}

	return mdl
}

// GetHealthModel returns the endpoint's health object.
//
// Must be called with e.Mutex locked.
func (e *Endpoint) getHealthModel() *models.EndpointHealth {
	// Duplicated from GetModelRLocked.
	currentState := models.EndpointState(e.state)
	if currentState == models.EndpointStateReady && e.status.CurrentStatus() != OK {
		currentState = models.EndpointStateNotReady
	}

	h := models.EndpointHealth{
		Bpf:           models.EndpointHealthStatusDisabled,
		Policy:        models.EndpointHealthStatusDisabled,
		Connected:     false,
		OverallHealth: models.EndpointHealthStatusDisabled,
	}
	switch currentState {
	case models.EndpointStateRegenerating, models.EndpointStateWaitingToRegenerate, models.EndpointStateDisconnecting:
		h = models.EndpointHealth{
			Bpf:           models.EndpointHealthStatusPending,
			Policy:        models.EndpointHealthStatusPending,
			Connected:     true,
			OverallHealth: models.EndpointHealthStatusPending,
		}
	case models.EndpointStateCreating:
		h = models.EndpointHealth{
			Bpf:           models.EndpointHealthStatusBootstrap,
			Policy:        models.EndpointHealthStatusDisabled,
			Connected:     true,
			OverallHealth: models.EndpointHealthStatusDisabled,
		}
	case models.EndpointStateWaitingForIdentity:
		h = models.EndpointHealth{
			Bpf:           models.EndpointHealthStatusDisabled,
			Policy:        models.EndpointHealthStatusBootstrap,
			Connected:     true,
			OverallHealth: models.EndpointHealthStatusDisabled,
		}
	case models.EndpointStateNotReady:
		h = models.EndpointHealth{
			Bpf:           models.EndpointHealthStatusWarning,
			Policy:        models.EndpointHealthStatusWarning,
			Connected:     true,
			OverallHealth: models.EndpointHealthStatusWarning,
		}
	case models.EndpointStateDisconnected:
		h = models.EndpointHealth{
			Bpf:           models.EndpointHealthStatusDisabled,
			Policy:        models.EndpointHealthStatusDisabled,
			Connected:     false,
			OverallHealth: models.EndpointHealthStatusDisabled,
		}
	case models.EndpointStateReady:
		h = models.EndpointHealth{
			Bpf:           models.EndpointHealthStatusOK,
			Policy:        models.EndpointHealthStatusOK,
			Connected:     true,
			OverallHealth: models.EndpointHealthStatusOK,
		}
	}

	return &h
}

// GetHealthModel returns the endpoint's health object.
func (e *Endpoint) GetHealthModel() *models.EndpointHealth {
	// NOTE: Using rlock on mutex directly because getHealthModel handles removed endpoint properly
	e.mutex.RLock()
	defer e.mutex.RUnlock()
	return e.getHealthModel()
}

// GetModel returns the API model of endpoint e.
func (e *Endpoint) GetModel() *models.Endpoint {
	if e == nil {
		return nil
	}
	// NOTE: Using rlock on mutex directly because GetModelRLocked handles removed endpoint properly
	e.mutex.RLock()
	defer e.mutex.RUnlock()

	return e.GetModelRLocked()
}

// GetPolicyModel returns the endpoint's policy as an API model.
//
// Must be called with e.Mutex locked.
func (e *Endpoint) GetPolicyModel() *models.EndpointPolicyStatus {
	if e == nil {
		return nil
	}

	if e.SecurityIdentity == nil {
		return nil
	}

	realizedIngressIdentities := make([]int64, 0)
	realizedEgressIdentities := make([]int64, 0)

	for policyMapKey := range e.realizedPolicy.PolicyMapState {
		if policyMapKey.DestPort != 0 {
			// If the port is non-zero, then the Key no longer only applies
			// at L3. AllowedIngressIdentities and AllowedEgressIdentities
			// contain sets of which identities (i.e., label-based L3 only)
			// are allowed, so anything which contains L4-related policy should
			// not be added to these sets.
			continue
		}
		switch trafficdirection.TrafficDirection(policyMapKey.TrafficDirection) {
		case trafficdirection.Ingress:
			realizedIngressIdentities = append(realizedIngressIdentities, int64(policyMapKey.Identity))
		case trafficdirection.Egress:
			realizedEgressIdentities = append(realizedEgressIdentities, int64(policyMapKey.Identity))
		default:
			log.WithField(logfields.TrafficDirection, trafficdirection.TrafficDirection(policyMapKey.TrafficDirection)).Error("Unexpected traffic direction present in realized PolicyMap state for endpoint")
		}
	}

	desiredIngressIdentities := make([]int64, 0)
	desiredEgressIdentities := make([]int64, 0)

	for policyMapKey := range e.desiredPolicy.PolicyMapState {
		if policyMapKey.DestPort != 0 {
			// If the port is non-zero, then the Key no longer only applies
			// at L3. AllowedIngressIdentities and AllowedEgressIdentities
			// contain sets of which identities (i.e., label-based L3 only)
			// are allowed, so anything which contains L4-related policy should
			// not be added to these sets.
			continue
		}
		switch trafficdirection.TrafficDirection(policyMapKey.TrafficDirection) {
		case trafficdirection.Ingress:
			desiredIngressIdentities = append(desiredIngressIdentities, int64(policyMapKey.Identity))
		case trafficdirection.Egress:
			desiredEgressIdentities = append(desiredEgressIdentities, int64(policyMapKey.Identity))
		default:
			log.WithField(logfields.TrafficDirection, trafficdirection.TrafficDirection(policyMapKey.TrafficDirection)).Error("Unexpected traffic direction present in desired PolicyMap state for endpoint")
		}
	}

	policyEnabled := e.policyStatus()

	e.proxyStatisticsMutex.RLock()
	proxyStats := make([]*models.ProxyStatistics, 0, len(e.proxyStatistics))
	for _, stats := range e.proxyStatistics {
		proxyStats = append(proxyStats, stats.DeepCopy())
	}
	e.proxyStatisticsMutex.RUnlock()
	sortProxyStats(proxyStats)

	var (
		realizedCIDRPolicy *policy.CIDRPolicy
		realizedL4Policy   *policy.L4Policy
	)
	if e.realizedPolicy != nil {
		realizedL4Policy = e.realizedPolicy.L4Policy
		realizedCIDRPolicy = e.realizedPolicy.CIDRPolicy
	}

	mdl := &models.EndpointPolicy{
		ID: int64(e.SecurityIdentity.ID),
		// This field should be removed.
		Build:                    int64(e.policyRevision),
		PolicyRevision:           int64(e.policyRevision),
		AllowedIngressIdentities: realizedIngressIdentities,
		AllowedEgressIdentities:  realizedEgressIdentities,
		CidrPolicy:               realizedCIDRPolicy.GetModel(),
		L4:                       realizedL4Policy.GetModel(),
		PolicyEnabled:            policyEnabled,
	}

	var (
		desiredCIDRPolicy *policy.CIDRPolicy
		desiredL4Policy   *policy.L4Policy
	)
	if e.desiredPolicy != nil {
		desiredCIDRPolicy = e.desiredPolicy.CIDRPolicy
		desiredL4Policy = e.desiredPolicy.L4Policy
	}

	desiredMdl := &models.EndpointPolicy{
		ID: int64(e.SecurityIdentity.ID),
		// This field should be removed.
		Build:                    int64(e.nextPolicyRevision),
		PolicyRevision:           int64(e.nextPolicyRevision),
		AllowedIngressIdentities: desiredIngressIdentities,
		AllowedEgressIdentities:  desiredEgressIdentities,
		CidrPolicy:               desiredCIDRPolicy.GetModel(),
		L4:                       desiredL4Policy.GetModel(),
		PolicyEnabled:            policyEnabled,
	}
	// FIXME GH-3280 Once we start returning revisions Realized should be the
	// policy implemented in the data path
	return &models.EndpointPolicyStatus{
		Spec:                desiredMdl,
		Realized:            mdl,
		ProxyPolicyRevision: int64(e.proxyPolicyRevision),
		ProxyStatistics:     proxyStats,
	}
}

// policyStatus returns the endpoint's policy status
//
// Must be called with e.Mutex locked.
func (e *Endpoint) policyStatus() models.EndpointPolicyEnabled {
	policyEnabled := models.EndpointPolicyEnabledNone
	switch {
	case e.realizedPolicy.IngressPolicyEnabled && e.realizedPolicy.EgressPolicyEnabled:
		policyEnabled = models.EndpointPolicyEnabledBoth
	case e.realizedPolicy.IngressPolicyEnabled:
		policyEnabled = models.EndpointPolicyEnabledIngress
	case e.realizedPolicy.EgressPolicyEnabled:
		policyEnabled = models.EndpointPolicyEnabledEgress
	}
	return policyEnabled
}

// ValidPatchTransitionState checks whether the state to which the provided
// model specifies is one to which an Endpoint can transition as part of a
// call to PATCH on an Endpoint.
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
func (e *Endpoint) ProcessChangeRequest(newEp *Endpoint, validPatchTransitionState bool) (string, error) {
	var (
		changed bool
		reason  string
	)

	if err := e.LockAlive(); err != nil {
		return "", err
	}
	defer e.Unlock()

	if newEp.ifIndex != 0 && e.ifIndex != newEp.ifIndex {
		e.ifIndex = newEp.ifIndex
		changed = true
	}

	if newEp.ifName != "" && e.ifName != newEp.ifName {
		e.ifName = newEp.ifName
		changed = true
	}

	// Only support transition to waiting-for-identity state, also
	// if the request is for ready state, as we will check the
	// existence of the security label below. Other transitions
	// are always internally managed, but we do not error out for
	// backwards compatibility.
	if newEp.state != "" &&
		validPatchTransitionState &&
		e.GetStateLocked() != StateWaitingForIdentity {
		// Will not change state if the current state does not allow the transition.
		if e.SetStateLocked(StateWaitingForIdentity, "Update endpoint from API PATCH") {
			changed = true
		}
	}

	if len(newEp.mac) != 0 && bytes.Compare(e.mac, newEp.mac) != 0 {
		e.mac = newEp.mac
		changed = true
	}

	if len(newEp.nodeMAC) != 0 && bytes.Compare(e.GetNodeMAC(), newEp.nodeMAC) != 0 {
		e.SetNodeMACLocked(newEp.nodeMAC)
		changed = true
	}

	if ip := newEp.IPv6; len(ip) != 0 && bytes.Compare(e.IPv6, newEp.IPv6) != 0 {
		e.IPv6 = newEp.IPv6
		changed = true
	}

	if ip := newEp.IPv4; len(ip) != 0 && bytes.Compare(e.IPv4, newEp.IPv4) != 0 {
		e.IPv4 = newEp.IPv4
		changed = true
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
		e.forcePolicyComputation()

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

// GetConfigurationStatus returns the Cilium API representation of the
// configuration of this endpoint.
func (e *Endpoint) GetConfigurationStatus() *models.EndpointConfigurationStatus {
	return &models.EndpointConfigurationStatus{
		Realized: &models.EndpointConfigurationSpec{
			LabelConfiguration: &models.LabelConfigurationSpec{
				User: e.OpLabels.Custom.GetModel(),
			},
			Options: *e.Options.GetMutableModel(),
		},
		Immutable: *e.Options.GetImmutableModel(),
	}
}

// ApplyUserLabelChanges changes the label configuration of the endpoint per the
// provided labels. Returns labels that were added and deleted. Returns an
// error if the endpoint is being deleted.
func (e *Endpoint) ApplyUserLabelChanges(lbls labels.Labels) (add, del labels.Labels, err error) {
	if err := e.RLockAlive(); err != nil {
		return nil, nil, err
	}
	defer e.RUnlock()
	add, del = e.OpLabels.SplitUserLabelChanges(lbls)
	return
}

// GetStatusModel returns the model of the status of this endpoint.
func (e *Endpoint) GetStatusModel() []*models.EndpointStatusChange {
	return e.status.GetModel()
}
