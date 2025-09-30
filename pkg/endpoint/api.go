// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

// This file contains functions related to conversion of information about
// an Endpoint to its corresponding Cilium API representation.

package endpoint

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"slices"
	"sort"
	"strconv"

	"go4.org/netipx"

	"github.com/cilium/cilium/api/v1/models"
	datapath "github.com/cilium/cilium/pkg/datapath/types"
	"github.com/cilium/cilium/pkg/endpoint/regeneration"
	"github.com/cilium/cilium/pkg/identity/cache"
	"github.com/cilium/cilium/pkg/identity/identitymanager"
	identitymodel "github.com/cilium/cilium/pkg/identity/model"
	"github.com/cilium/cilium/pkg/ipcache"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/labels/model"
	"github.com/cilium/cilium/pkg/labelsfilter"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/mac"
	"github.com/cilium/cilium/pkg/maps/ctmap"
	"github.com/cilium/cilium/pkg/maps/policymap"
	monitoragent "github.com/cilium/cilium/pkg/monitor/agent"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/policy/trafficdirection"
	"github.com/cilium/cilium/pkg/types"
	"github.com/cilium/cilium/pkg/u8proto"
	wgTypes "github.com/cilium/cilium/pkg/wireguard/types"
)

// GetLabelsModel returns the labels of the endpoint in their representation
// for the Cilium API. Returns an error if the Endpoint is being deleted.
func (e *Endpoint) GetLabelsModel() (*models.LabelConfiguration, error) {
	if err := e.rlockAlive(); err != nil {
		return nil, err
	}
	spec := &models.LabelConfigurationSpec{
		User: e.labels.Custom.GetModel(),
	}

	cfg := models.LabelConfiguration{
		Spec: spec,
		Status: &models.LabelConfigurationStatus{
			Realized:         spec,
			SecurityRelevant: e.labels.OrchestrationIdentity.GetModel(),
			Derived:          e.labels.OrchestrationInfo.GetModel(),
			Disabled:         e.labels.Disabled.GetModel(),
		},
	}
	e.runlock()
	return &cfg, nil
}

// NewEndpointFromChangeModel creates a new endpoint from a request
func NewEndpointFromChangeModel(ctx context.Context, logger *slog.Logger, dnsRulesAPI DNSRulesAPI, epBuildQueue EndpointBuildQueue, loader datapath.Loader, orchestrator datapath.Orchestrator, compilationLock datapath.CompilationLock, bandwidthManager datapath.BandwidthManager, ipTablesManager datapath.IptablesManager, identityManager identitymanager.IDManager, monitorAgent monitoragent.Agent, policyMapFactory policymap.Factory, policyRepo policy.PolicyRepository, namedPortsGetter namedPortsGetter, proxy EndpointProxy, allocator cache.IdentityAllocator, ctMapGC ctmap.GCRunner, kvstoreSyncher *ipcache.IPIdentitySynchronizer, model *models.EndpointChangeRequest, wgCfg wgTypes.WireguardConfig, ipsecCfg datapath.IPsecConfig, policyDebugLog io.Writer) (*Endpoint, error) {
	if model == nil {
		return nil, nil
	}

	ep := createEndpoint(logger, dnsRulesAPI, epBuildQueue, loader, orchestrator, compilationLock, bandwidthManager, ipTablesManager, identityManager, monitorAgent, policyMapFactory, policyRepo, namedPortsGetter, proxy, allocator, ctMapGC, kvstoreSyncher, uint16(model.ID), model.InterfaceName, wgCfg, ipsecCfg, policyDebugLog)
	ep.ifIndex = int(model.InterfaceIndex)
	ep.containerIfName = model.ContainerInterfaceName
	ep.containerNetnsPath = model.ContainerNetnsPath
	ep.parentIfIndex = int(model.ParentInterfaceIndex)
	if model.ContainerName != "" {
		ep.containerName.Store(&model.ContainerName)
	}
	if model.ContainerID != "" {
		ep.containerID.Store(&model.ContainerID)
	}
	ep.dockerNetworkID = model.DockerNetworkID
	ep.dockerEndpointID = model.DockerEndpointID
	ep.K8sPodName = model.K8sPodName
	ep.K8sNamespace = model.K8sNamespace
	ep.K8sUID = model.K8sUID
	ep.IPv4Enabled = model.IPV4Enabled
	ep.IPv6Enabled = model.IPV6Enabled
	ep.disableLegacyIdentifiers = model.DisableLegacyIdentifiers

	if model.Mac != "" {
		m, err := mac.ParseMAC(model.Mac)
		if err != nil {
			return nil, err
		}
		ep.mac = m
	}

	if model.HostMac != "" {
		m, err := mac.ParseMAC(model.HostMac)
		if err != nil {
			return nil, err
		}
		ep.nodeMAC = m
	}

	if model.NetnsCookie != "" {
		cookie64, err := strconv.ParseInt(model.NetnsCookie, 10, 64)
		if err != nil {
			// Don't return on error (and block the endpoint creation) as this
			// is an unusual case where data could have been malformed. Defer error
			// logging to individual features depending on the metadata.
			ep.getLogger().Error(
				"unable to parse netns cookie for ep",
				logfields.Error, err,
				logfields.NetnsCookie, model.NetnsCookie,
				logfields.EndpointID, model.ID,
			)
		} else {
			ep.NetNsCookie = uint64(cookie64)
		}
	}

	if model.Addressing != nil {
		if ip := model.Addressing.IPV6; ip != "" {
			ip6, err := netipx.ParsePrefixOrAddr(ip)
			if err != nil {
				return nil, err
			}
			if !ip6.Is6() {
				return nil, fmt.Errorf("invalid IPv6 address %q", ip)
			}
			ep.IPv6 = ip6
			ep.IPv6IPAMPool = model.Addressing.IPV6PoolName
		}

		if ip := model.Addressing.IPV4; ip != "" {
			ip4, err := netipx.ParsePrefixOrAddr(ip)
			if err != nil {
				return nil, err
			}
			if !ip4.Is4() {
				return nil, fmt.Errorf("invalid IPv4 address %q", ip)
			}
			ep.IPv4 = ip4
			ep.IPv4IPAMPool = model.Addressing.IPV4PoolName
		}
	}

	if model.DatapathConfiguration != nil {
		ep.DatapathConfiguration = *model.DatapathConfiguration
		// We need to make sure DatapathConfiguration.DisableSipVerification value
		// overrides the value of SourceIPVerification runtime option of the endpoint.
		if ep.DatapathConfiguration.DisableSipVerification {
			ep.updateAndOverrideEndpointOptions(option.OptionMap{option.SourceIPVerification: option.OptionDisabled})
		}
	}

	if model.Labels != nil {
		lbls := labels.NewLabelsFromModel(model.Labels)
		identityLabels, infoLabels := labelsfilter.Filter(lbls)
		ep.labels.OrchestrationIdentity = identityLabels
		ep.labels.OrchestrationInfo = infoLabels
	}

	if model.State != nil {
		ep.setState(State(*model.State), "Endpoint creation")
	}

	if model.Properties != nil {
		ep.properties = model.Properties
	}

	return ep, nil
}

func (e *Endpoint) getModelEndpointIdentitiersRLocked() *models.EndpointIdentifiers {
	identifiers := &models.EndpointIdentifiers{
		CniAttachmentID:  e.GetCNIAttachmentID(),
		DockerEndpointID: e.dockerEndpointID,
		DockerNetworkID:  e.dockerNetworkID,
	}

	// Use legacy endpoint identifiers only if the endpoint has not opted out
	if !e.disableLegacyIdentifiers {
		identifiers.ContainerID = e.GetContainerID()
		identifiers.ContainerName = e.GetContainerName()
		identifiers.PodName = e.GetK8sNamespaceAndPodName()
		identifiers.K8sPodName = e.K8sPodName
		identifiers.K8sNamespace = e.K8sNamespace
	}

	return identifiers
}

func (e *Endpoint) getModelNetworkingRLocked() *models.EndpointNetworking {
	return &models.EndpointNetworking{
		Addressing: []*models.AddressPair{{
			IPV4:         e.GetIPv4Address(),
			IPV4PoolName: e.IPv4IPAMPool,
			IPV6:         e.GetIPv6Address(),
			IPV6PoolName: e.IPv6IPAMPool,
		}},
		InterfaceIndex:         int64(e.ifIndex),
		InterfaceName:          e.ifName,
		ContainerInterfaceName: e.containerIfName,
		Mac:                    e.mac.String(),
		HostMac:                e.nodeMAC.String(),
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

	lblMdl := model.NewModel(&e.labels)

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
func (e *Endpoint) getNamedPortsModel() models.NamedPorts {
	var k8sPorts types.NamedPortMap
	if p := e.k8sPorts.Load(); p != nil {
		k8sPorts = *p
	}

	np := make(models.NamedPorts, 0, len(k8sPorts))
	// keep named ports ordered to avoid the unnecessary updates to
	// kube-apiserver
	for _, name := range slices.Sorted(maps.Keys(k8sPorts)) {
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

// getIdentities returns the ingress and egress identities stored in the
// MapState.
// Used only for API requests.
func getIdentities(ep *policy.EndpointPolicy) (ingIdentities, ingDenyIdentities, egIdentities, egDenyIdentities []int64) {
	for key, entry := range ep.Entries() {
		if key.Nexthdr != 0 || key.DestPort != 0 {
			// If the protocol or port is non-zero, then the Key no longer only applies
			// at L3. AllowedIngressIdentities and AllowedEgressIdentities
			// contain sets of which identities (i.e., label-based L3 only)
			// are allowed, so anything which contains L4-related policy should
			// not be added to these sets.
			continue
		}
		if key.TrafficDirection() == trafficdirection.Ingress {
			if entry.IsDeny() {
				ingDenyIdentities = append(ingDenyIdentities, int64(key.Identity))
			} else {
				ingIdentities = append(ingIdentities, int64(key.Identity))
			}
		} else {
			if entry.IsDeny() {
				egDenyIdentities = append(egDenyIdentities, int64(key.Identity))
			} else {
				egIdentities = append(egIdentities, int64(key.Identity))
			}
		}
	}

	slices.Sort(ingIdentities)
	slices.Sort(ingDenyIdentities)
	slices.Sort(egIdentities)
	slices.Sort(egDenyIdentities)

	return slices.Compact(ingIdentities), slices.Compact(ingDenyIdentities),
		slices.Compact(egIdentities), slices.Compact(egDenyIdentities)
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

	realizedIngressIdentities, realizedDenyIngressIdentities, realizedEgressIdentities, realizedDenyEgressIdentities := getIdentities(e.realizedPolicy)

	desiredIngressIdentities, desiredDenyIngressIdentities, desiredEgressIdentities, desiredDenyEgressIdentities := getIdentities(e.desiredPolicy)

	policyEnabled := e.policyStatus()

	e.proxyStatisticsMutex.RLock()
	proxyStats := make([]*models.ProxyStatistics, 0, len(e.proxyStatistics))
	for _, stats := range e.proxyStatistics {
		proxyStats = append(proxyStats, stats.DeepCopy())
	}
	e.proxyStatisticsMutex.RUnlock()
	sortProxyStats(proxyStats)

	var realizedL4Policy *policy.L4Policy
	if e.realizedPolicy != nil {
		realizedL4Policy = &e.realizedPolicy.L4Policy
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

	var desiredL4Policy *policy.L4Policy
	if e.desiredPolicy != nil {
		desiredL4Policy = &e.desiredPolicy.L4Policy
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
//
// Before adding any new fields here, check to see if they are assumed to be mutable after
// endpoint creation!
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

	if newContainerName := newEp.containerName.Load(); newContainerName != nil && *newContainerName != "" {
		e.containerName.Store(newContainerName)
		// no need to set changed here
	}

	if newContainerID := newEp.containerID.Load(); newContainerID != nil && *newContainerID != "" {
		e.containerID.Store(newContainerID)
		// no need to set changed here
	}

	e.replaceInformationLabels(labels.LabelSourceAny, newEp.labels.OrchestrationInfo)
	rev := e.replaceIdentityLabels(labels.LabelSourceAny, newEp.labels.IdentityLabels())
	if rev != 0 {
		// Run as a goroutine since the runIdentityResolver needs to get the lock
		go e.runIdentityResolver(e.aliveCtx, false, 0)
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
			if e.skippedRegenerationLevel < regeneration.RegenerateWithDatapath {
				e.skippedRegenerationLevel = regeneration.RegenerateWithDatapath
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
				User: e.labels.Custom.GetModel(),
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
	add, del = e.labels.SplitUserLabelChanges(lbls)
	return
}

// GetStatusModel returns the model of the status of this endpoint.
func (e *Endpoint) GetStatusModel() []*models.EndpointStatusChange {
	return e.status.GetModel()
}
