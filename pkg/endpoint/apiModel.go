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
