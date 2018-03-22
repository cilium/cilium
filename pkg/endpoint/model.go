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
	"sort"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/common/addressing"
	pkgLabels "github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/mac"
)

// NewEndpointFromChangeModel creates a new endpoint from a request
func NewEndpointFromChangeModel(base *models.EndpointChangeRequest, l pkgLabels.Labels) (*Endpoint, error) {
	if base == nil {
		return nil, nil
	}

	ep := &Endpoint{
		ID:               uint16(base.ID),
		ContainerName:    base.ContainerName,
		DockerID:         base.ContainerID,
		DockerNetworkID:  base.DockerNetworkID,
		DockerEndpointID: base.DockerEndpointID,
		IfName:           base.InterfaceName,
		IfIndex:          int(base.InterfaceIndex),
		OpLabels: pkgLabels.OpLabels{
			Custom:                pkgLabels.Labels{},
			Disabled:              pkgLabels.Labels{},
			OrchestrationIdentity: l.DeepCopy(),
			OrchestrationInfo:     pkgLabels.Labels{},
		},
		state:  string(base.State),
		Status: NewEndpointStatus(),
	}

	if base.Mac != "" {
		m, err := mac.ParseMAC(base.Mac)
		if err != nil {
			return nil, err
		}
		ep.LXCMAC = m
	}

	if base.HostMac != "" {
		m, err := mac.ParseMAC(base.HostMac)
		if err != nil {
			return nil, err
		}
		ep.NodeMAC = m
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

	return ep, nil
}

// GetModelRLocked returns the API model of endpoint e.
// e.Mutex must be RLocked.
func (e *Endpoint) GetModelRLocked() *models.Endpoint {
	policy := models.EndpointPolicyEnabledNone
	if e == nil {
		return nil
	}

	currentState := models.EndpointState(e.state)
	if currentState == models.EndpointStateReady && e.Status.CurrentStatus() != OK {
		currentState = models.EndpointStateNotReady
	}

	policyIngressEnabled := e.Opts.IsEnabled(OptionIngressPolicy)
	policyEgressEnabled := e.Opts.IsEnabled(OptionEgressPolicy)

	if policyIngressEnabled && policyEgressEnabled {
		policy = models.EndpointPolicyEnabledBoth
	} else if policyIngressEnabled {
		policy = models.EndpointPolicyEnabledIngress
	} else if policyEgressEnabled {
		policy = models.EndpointPolicyEnabledEgress
	}

	// This returns the most recent log entry for this endpoint. It is backwards
	// compatible with the json from before we added `cilium endpoint log` but it
	// only returns 1 entry.
	statusLog := e.Status.GetModel()
	if len(statusLog) > 0 {
		statusLog = statusLog[:1]
	}

	mdl := &models.Endpoint{
		ID:               int64(e.ID),
		Configuration:    e.Opts.GetModel(),
		ContainerID:      e.DockerID,
		ContainerName:    e.ContainerName,
		DockerEndpointID: e.DockerEndpointID,
		DockerNetworkID:  e.DockerNetworkID,
		Identity:         e.SecurityIdentity.GetModel(),
		InterfaceIndex:   int64(e.IfIndex),
		InterfaceName:    e.IfName,
		Labels: &models.LabelConfiguration{
			Custom:                e.OpLabels.Custom.GetModel(),
			OrchestrationIdentity: e.OpLabels.OrchestrationIdentity.GetModel(),
			OrchestrationInfo:     e.OpLabels.OrchestrationInfo.GetModel(),
			Disabled:              e.OpLabels.Disabled.GetModel(),
		},
		Mac:                 e.LXCMAC.String(),
		HostMac:             e.NodeMAC.String(),
		PodName:             e.GetK8sNamespaceAndPodNameLocked(),
		State:               currentState, // TODO: Validate
		Status:              statusLog,
		Health:              e.getHealthModel(),
		Policy:              e.GetPolicyModel(),
		PolicyEnabled:       &policy,
		PolicyRevision:      int64(e.policyRevision),
		ProxyPolicyRevision: int64(e.proxyPolicyRevision),
		Addressing: &models.EndpointAddressing{
			IPV4: e.IPv4.String(),
			IPV6: e.IPv6.String(),
		},
		Controllers: e.controllers.GetStatusModel(),
	}

	// Sort these slices since they come out in random orders. This allows
	// reflect.DeepEqual to succeed.
	sort.StringSlice(mdl.Labels.Custom).Sort()
	sort.StringSlice(mdl.Labels.Disabled).Sort()
	sort.StringSlice(mdl.Labels.OrchestrationIdentity).Sort()
	sort.StringSlice(mdl.Labels.OrchestrationInfo).Sort()
	sort.Slice(mdl.Controllers, func(i, j int) bool { return mdl.Controllers[i].Name < mdl.Controllers[j].Name })
	return mdl
}

// GetHealthModel returns the endpoint's health object.
//
// Must be called with e.Mutex locked.
func (e *Endpoint) getHealthModel() *models.EndpointHealth {
	// Duplicated from GetModelRLocked.
	currentState := models.EndpointState(e.state)
	if currentState == models.EndpointStateReady && e.Status.CurrentStatus() != OK {
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
	e.Mutex.RLock()
	defer e.Mutex.RUnlock()
	return e.getHealthModel()
}

// GetModel returns the API model of endpoint e.
func (e *Endpoint) GetModel() *models.Endpoint {
	if e == nil {
		return nil
	}
	e.Mutex.RLock()
	defer e.Mutex.RUnlock()

	return e.GetModelRLocked()
}

// GetPolicyModel returns the endpoint's policy as an API model.
//
// Must be called with e.Mutex locked.
func (e *Endpoint) GetPolicyModel() *models.EndpointPolicy {
	if e == nil {
		return nil
	}

	if e.Consumable == nil {
		return nil
	}

	e.Consumable.Mutex.RLock()
	defer e.Consumable.Mutex.RUnlock()

	ingressIdentities := make([]int64, 0, len(e.Consumable.IngressIdentities))
	for ingressIdentity := range e.Consumable.IngressIdentities {
		ingressIdentities = append(ingressIdentities, int64(ingressIdentity))
	}

	return &models.EndpointPolicy{
		ID:    int64(e.Consumable.ID),
		Build: int64(e.Consumable.Iteration),
		AllowedIngressIdentities: ingressIdentities,
		CidrPolicy:               e.L3Policy.GetModel(),
		L4:                       e.Consumable.L4Policy.GetModel(),
	}
}

type orderEndpoint func(e1, e2 *models.Endpoint) bool

// OrderEndpointAsc orders the slice of Endpoint in ascending ID order.
func OrderEndpointAsc(eps []*models.Endpoint) {
	ascPriority := func(e1, e2 *models.Endpoint) bool {
		return e1.ID < e2.ID
	}
	orderEndpoint(ascPriority).sort(eps)
}

func (by orderEndpoint) sort(eps []*models.Endpoint) {
	dS := &epSorter{
		eps: eps,
		by:  by,
	}
	sort.Sort(dS)
}

type epSorter struct {
	eps []*models.Endpoint
	by  func(e1, e2 *models.Endpoint) bool
}

func (epS *epSorter) Len() int {
	return len(epS.eps)
}

func (epS *epSorter) Swap(i, j int) {
	epS.eps[i], epS.eps[j] = epS.eps[j], epS.eps[i]
}

func (epS *epSorter) Less(i, j int) bool {
	return epS.by(epS.eps[i], epS.eps[j])
}
