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
	if e == nil {
		return nil
	}

	currentState := models.EndpointState(e.state)
	if currentState == models.EndpointStateReady && e.Status.CurrentStatus() != OK {
		currentState = models.EndpointStateNotReady
	}

	// This returns the most recent log entry for this endpoint. It is backwards
	// compatible with the json from before we added `cilium endpoint log` but it
	// only returns 1 entry.
	statusLog := e.Status.GetModel()
	if len(statusLog) > 0 {
		statusLog = statusLog[:1]
	}

	lblSpec := &models.LabelConfigurationSpec{
		User: e.OpLabels.Custom.GetModel(),
	}
	lblMdl := &models.LabelConfigurationStatus{
		Realized:         lblSpec,
		SecurityRelevant: e.OpLabels.OrchestrationIdentity.GetModel(),
		Derived:          e.OpLabels.OrchestrationInfo.GetModel(),
		Disabled:         e.OpLabels.Disabled.GetModel(),
	}
	// Sort these slices since they come out in random orders. This allows
	// reflect.DeepEqual to succeed.
	sort.StringSlice(lblSpec.User).Sort()
	sort.StringSlice(lblMdl.Disabled).Sort()
	sort.StringSlice(lblMdl.SecurityRelevant).Sort()
	sort.StringSlice(lblMdl.Derived).Sort()

	controllerMdl := e.controllers.GetStatusModel()
	sort.Slice(controllerMdl, func(i, j int) bool { return controllerMdl[i].Name < controllerMdl[j].Name })

	spec := &models.EndpointConfigurationSpec{
		LabelConfiguration: lblSpec,
		Options:            *e.Opts.GetMutableModel(),
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
				InterfaceIndex: int64(e.IfIndex),
				InterfaceName:  e.IfName,
				Mac:            e.LXCMAC.String(),
				HostMac:        e.NodeMAC.String(),
			},
			ExternalIdentifiers: &models.EndpointIdentifiers{
				ContainerID:      e.DockerID,
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

// GetModel returns the API model of endpoint e.
func (e *Endpoint) GetModel() *models.Endpoint {
	if e == nil {
		return nil
	}
	e.Mutex.RLock()
	defer e.Mutex.RUnlock()

	return e.GetModelRLocked()
}
