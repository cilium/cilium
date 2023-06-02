// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

// This file contains functions related to conversion of information about
// an Endpoint to its corresponding Cilium API representation.

package endpoint

import (
	"bytes"
	"context"
	"fmt"
	"net/netip"
	"sort"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/endpoint/regeneration"
	"github.com/cilium/cilium/pkg/identity/cache"
	identitymodel "github.com/cilium/cilium/pkg/identity/model"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/labels/model"
	"github.com/cilium/cilium/pkg/labelsfilter"
	"github.com/cilium/cilium/pkg/mac"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/u8proto"
)

// GetLabelsModel returns the labels of the endpoint in their representation
// for the Cilium API. Returns an error if the Endpoint is being deleted.
func (e *Endpoint) GetLabelsModel() (*models.LabelConfiguration, error) {
	if err := e.rlockAlive(); err != nil {
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
	e.runlock()
	return &cfg, nil
}

func parsePrefixOrAddr(ip string) (netip.Addr, error) {
	prefix, err := netip.ParsePrefix(ip)
	if err != nil {
		return netip.ParseAddr(ip)
	}
	return prefix.Addr(), nil
}

// NewEndpointFromChangeModel creates a new endpoint from a request
func NewEndpointFromChangeModel(ctx context.Context, owner regeneration.Owner, policyGetter policyRepoGetter, namedPortsGetter namedPortsGetter, proxy EndpointProxy, allocator cache.IdentityAllocator, base *models.EndpointChangeRequest) (*Endpoint, error) {
	if base == nil {
		return nil, nil
	}

	ep := createEndpoint(owner, policyGetter, namedPortsGetter, proxy, allocator, uint16(base.ID), base.InterfaceName)
	ep.ifIndex = int(base.InterfaceIndex)
	ep.containerName = base.ContainerName
	ep.containerID = base.ContainerID
	ep.dockerNetworkID = base.DockerNetworkID
	ep.dockerEndpointID = base.DockerEndpointID
	ep.K8sPodName = base.K8sPodName
	ep.K8sNamespace = base.K8sNamespace

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
			ip6, err := parsePrefixOrAddr(ip)
			if err != nil {
				return nil, err
			}
			if !ip6.Is6() {
				return nil, fmt.Errorf("invalid IPv6 address %q", ip)
			}
			ep.IPv6 = ip6
			ep.IPv6IPAMPool = base.Addressing.IPV6PoolName
		}

		if ip := base.Addressing.IPV4; ip != "" {
			ip4, err := parsePrefixOrAddr(ip)
			if err != nil {
				return nil, err
			}
			if !ip4.Is4() {
				return nil, fmt.Errorf("invalid IPv4 address %q", ip)
			}
			ep.IPv4 = ip4
			ep.IPv4IPAMPool = base.Addressing.IPV4PoolName
		}
	}

	if base.DatapathConfiguration != nil {
		ep.DatapathConfiguration = *base.DatapathConfiguration
	}

	if base.Labels != nil {
		lbls := labels.NewLabelsFromModel(base.Labels)
		identityLabels, infoLabels := labelsfilter.Filter(lbls)
		ep.OpLabels.OrchestrationIdentity = identityLabels
		ep.OpLabels.OrchestrationInfo = infoLabels
	}

	if base.State != nil {
		ep.setState(State(*base.State), "Endpoint creation")
	}

	return ep, nil
}

func (e *Endpoint) getModelEndpointIdentitiersRLocked() *models.EndpointIdentifiers {
	return &models.EndpointIdentifiers{
		ContainerID:      e.containerID,
		ContainerName:    e.containerName,
		DockerEndpointID: e.dockerEndpointID,
		DockerNetworkID:  e.dockerNetworkID,
		PodName:          e.getK8sNamespaceAndPodName(),
		K8sPodName:       e.K8sPodName,
		K8sNamespace:     e.K8sNamespace,
	}
}

func (e *Endpoint) getModelNetworkingRLocked() *models.EndpointNetworking {
	return &models.EndpointNetworking{
		Addressing: []*models.AddressPair{{
			IPV4:         e.GetIPv4Address(),
			IPV4PoolName: e.IPv4IPAMPool,
			IPV6:         e.GetIPv6Address(),
			IPV6PoolName: e.IPv6IPAMPool,
		}},
		InterfaceIndex: int64(e.ifIndex),
		InterfaceName:  e.ifName,
		Mac:            e.mac.String(),
		HostMac:        e.nodeMAC.String(),
	}
}

func (e *Endpoint) getModelCurrentStateRLocked() models.EndpointState {
	currentState := models.EndpointState(e.state)
	if currentState == models.EndpointStateReady && e.status.CurrentStatus() != OK {
		return models.EndpointStateNotDashReady
	}
	return currentState
}

// GetModelRLocked returns the API model of endpoint e.
// e.mutex must be RLocked.
func (e *Endpoint) GetModelRLocked() *models.Endpoint {
	if e == nil {
		return nil
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
			Realized:            spec,
			Identity:            identitymodel.CreateModel(e.SecurityIdentity),
			Labels:              lblMdl,
			Networking:          e.getModelNetworkingRLocked(),
			ExternalIdentifiers: e.getModelEndpointIdentitiersRLocked(),
			// FIXME GH-3280 When we begin returning endpoint revisions this should
			// change to return the configured and in-datapath policies.
			Policy:      e.GetPolicyModel(),
			Log:         statusLog,
			Controllers: controllerMdl,
			State:       e.getModelCurrentStateRLocked().Pointer(), // TODO: Validate
			Health:      e.getHealthModel(),
			NamedPorts:  e.getNamedPortsModel(),
		},
	}

	return mdl
}

// GetHealthModel returns the endpoint's health object.
//
// Must be called with e.mutex RLock()ed.
func (e *Endpoint) getHealthModel() *models.EndpointHealth {
	// Duplicated from GetModelRLocked.
	currentState := models.EndpointState(e.state)
	if currentState == models.EndpointStateReady && e.status.CurrentStatus() != OK {
		currentState = models.EndpointStateNotDashReady
	}

	h := models.EndpointHealth{
		Bpf:           models.EndpointHealthStatusDisabled,
		Policy:        models.EndpointHealthStatusDisabled,
		Connected:     false,
		OverallHealth: models.EndpointHealthStatusDisabled,
	}
	switch currentState {
	case models.EndpointStateRegenerating, models.EndpointStateWaitingDashToDashRegenerate, models.EndpointStateDisconnecting:
		h = models.EndpointHealth{
			Bpf:           models.EndpointHealthStatusPending,
			Policy:        models.EndpointHealthStatusPending,
			Connected:     true,
			OverallHealth: models.EndpointHealthStatusPending,
		}
	case models.EndpointStateWaitingDashForDashIdentity:
		h = models.EndpointHealth{
			Bpf:           models.EndpointHealthStatusDisabled,
			Policy:        models.EndpointHealthStatusBootstrap,
			Connected:     true,
			OverallHealth: models.EndpointHealthStatusDisabled,
		}
	case models.EndpointStateNotDashReady:
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

// getNamedPortsModel returns the endpoint's NamedPorts object.
//
// Must be called with e.mutex RLock()ed.
func (e *Endpoint) getNamedPortsModel() (np models.NamedPorts) {
	k8sPorts := e.k8sPorts
	// keep named ports ordered to avoid the unnecessary updates to
	// kube-apiserver
	names := make([]string, 0, len(k8sPorts))
	for name := range k8sPorts {
		names = append(names, name)
	}
	sort.Strings(names)

	np = make(models.NamedPorts, 0, len(k8sPorts))
	for _, name := range names {
		value := k8sPorts[name]
		np = append(np, &models.Port{
			Name:     name,
			Port:     value.Port,
			Protocol: u8proto.U8proto(value.Proto).String(),
		})
	}
	return np
}

// GetNamedPortsModel returns the endpoint's NamedPorts object.
func (e *Endpoint) GetNamedPortsModel() models.NamedPorts {
	if err := e.rlockAlive(); err != nil {
		return nil
	}
	defer e.runlock()
	return e.getNamedPortsModel()
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
// Must be called with e.mutex RLock()ed.
func (e *Endpoint) GetPolicyModel() *models.EndpointPolicyStatus {
	if e == nil {
		return nil
	}

	if e.SecurityIdentity == nil {
		return nil
	}

	realizedLog := log.WithField("map-name", "realized").Logger
	realizedIngressIdentities, realizedEgressIdentities :=
		e.realizedPolicy.PolicyMapState.GetIdentities(realizedLog)

	realizedDenyIngressIdentities, realizedDenyEgressIdentities :=
		e.realizedPolicy.PolicyMapState.GetDenyIdentities(realizedLog)

	desiredLog := log.WithField("map-name", "desired").Logger
	desiredIngressIdentities, desiredEgressIdentities :=
		e.desiredPolicy.PolicyMapState.GetIdentities(desiredLog)

	desiredDenyIngressIdentities, desiredDenyEgressIdentities :=
		e.desiredPolicy.PolicyMapState.GetDenyIdentities(desiredLog)

	policyEnabled := e.policyStatus()

	e.proxyStatisticsMutex.RLock()
	proxyStats := make([]*models.ProxyStatistics, 0, len(e.proxyStatistics))
	for _, stats := range e.proxyStatistics {
		proxyStats = append(proxyStats, stats.DeepCopy())
	}
	e.proxyStatisticsMutex.RUnlock()
	sortProxyStats(proxyStats)

	var (
		realizedL4Policy *policy.L4Policy
	)
	if e.realizedPolicy != nil {
		realizedL4Policy = e.realizedPolicy.L4Policy
	}

	mdl := &models.EndpointPolicy{
		ID: int64(e.SecurityIdentity.ID),
		// This field should be removed.
		Build:                    int64(e.policyRevision),
		PolicyRevision:           int64(e.policyRevision),
		AllowedIngressIdentities: realizedIngressIdentities,
		AllowedEgressIdentities:  realizedEgressIdentities,
		DeniedIngressIdentities:  realizedDenyIngressIdentities,
		DeniedEgressIdentities:   realizedDenyEgressIdentities,
		L4:                       realizedL4Policy.GetModel(),
		PolicyEnabled:            policyEnabled,
	}

	var (
		desiredL4Policy *policy.L4Policy
	)
	if e.desiredPolicy != nil {
		desiredL4Policy = e.desiredPolicy.L4Policy
	}

	desiredMdl := &models.EndpointPolicy{
		ID: int64(e.SecurityIdentity.ID),
		// This field should be removed.
		Build:                    int64(e.nextPolicyRevision),
		PolicyRevision:           int64(e.nextPolicyRevision),
		AllowedIngressIdentities: desiredIngressIdentities,
		AllowedEgressIdentities:  desiredEgressIdentities,
		DeniedIngressIdentities:  desiredDenyIngressIdentities,
		DeniedEgressIdentities:   desiredDenyEgressIdentities,
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
// Must be called with e.mutex RLock()ed.
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

	if e.Options.IsEnabled(option.PolicyAuditMode) {
		switch policyEnabled {
		case models.EndpointPolicyEnabledIngress:
			return models.EndpointPolicyEnabledAuditDashIngress
		case models.EndpointPolicyEnabledEgress:
			return models.EndpointPolicyEnabledAuditDashEgress
		case models.EndpointPolicyEnabledBoth:
			return models.EndpointPolicyEnabledAuditDashBoth
		}
	}

	return policyEnabled
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

	if err := e.lockAlive(); err != nil {
		return "", err
	}
	defer e.unlock()

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
		e.getState() != StateWaitingForIdentity {
		// Will not change state if the current state does not allow the transition.
		if e.setState(StateWaitingForIdentity, "Update endpoint from API PATCH") {
			changed = true
		}
	}

	if len(newEp.mac) != 0 && bytes.Compare(e.mac, newEp.mac) != 0 {
		e.mac = newEp.mac
		changed = true
	}

	if len(newEp.nodeMAC) != 0 && bytes.Compare(e.GetNodeMAC(), newEp.nodeMAC) != 0 {
		e.nodeMAC = newEp.nodeMAC
		changed = true
	}

	if newEp.IPv6.IsValid() && e.IPv6 != newEp.IPv6 {
		e.IPv6 = newEp.IPv6
		e.IPv6IPAMPool = newEp.IPv6IPAMPool
		changed = true
	}

	if newEp.IPv4.IsValid() && e.IPv4 != newEp.IPv4 {
		e.IPv4 = newEp.IPv4
		e.IPv4IPAMPool = newEp.IPv4IPAMPool
		changed = true
	}

	if newEp.containerName != "" && e.containerName != newEp.containerName {
		e.containerName = newEp.containerName
	}

	if newEp.containerID != "" && e.containerID != newEp.containerID {
		e.containerID = newEp.containerID
	}

	e.replaceInformationLabels(newEp.OpLabels.OrchestrationInfo)
	rev := e.replaceIdentityLabels(newEp.OpLabels.IdentityLabels())
	if rev != 0 {
		// Run as a goroutine since the runIdentityResolver needs to get the lock
		go e.runIdentityResolver(e.aliveCtx, rev, false)
	}

	// If desired state is waiting-for-identity but identity is already
	// known, bump it to ready state immediately to force re-generation
	if newEp.state == StateWaitingForIdentity && e.SecurityIdentity != nil {
		e.setState(StateReady, "Preparing to force endpoint regeneration because identity is known while handling API PATCH")
		changed = true
	}

	if changed {
		// Force policy regeneration as endpoint's configuration was changed.
		// Other endpoints need not be regenerated as no labels were changed.
		// Note that we still need to (eventually) regenerate the endpoint for
		// the changes to take effect.
		e.forcePolicyComputation()

		// Transition to waiting-to-regenerate if ready.
		if e.getState() == StateReady {
			e.setState(StateWaitingToRegenerate, "Forcing endpoint regeneration because identity is known while handling API PATCH")
		}

		switch e.getState() {
		case StateWaitingToRegenerate:
			reason = "Waiting on endpoint regeneration because identity is known while handling API PATCH"
		case StateWaitingForIdentity:
			reason = "Waiting on endpoint initial program regeneration while handling API PATCH"
		default:
			// Caller skips regeneration if reason == "". Bump the skipped regeneration level so that next
			// regeneration will realise endpoint changes.
			if e.skippedRegenerationLevel < regeneration.RegenerateWithDatapathRewrite {
				e.skippedRegenerationLevel = regeneration.RegenerateWithDatapathRewrite
			}
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
	if err := e.rlockAlive(); err != nil {
		return nil, nil, err
	}
	defer e.runlock()
	add, del = e.OpLabels.SplitUserLabelChanges(lbls)
	return
}

// GetStatusModel returns the model of the status of this endpoint.
func (e *Endpoint) GetStatusModel() []*models.EndpointStatusChange {
	return e.status.GetModel()
}
