// Copyright 2019 Authors of Hubble
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
	"net"
	"sort"
	"time"

	"github.com/cilium/cilium/api/v1/models"
	monitorAPI "github.com/cilium/cilium/pkg/monitor/api"

	v1 "github.com/cilium/hubble/pkg/api/v1"
	"github.com/cilium/hubble/pkg/k8s"
)

// ParseEndpointFromModel parses all elements from modelEP into a Endpoint.
func ParseEndpointFromModel(modelEP *models.Endpoint) *v1.Endpoint {
	var ns, podName, containerID string
	var labels []string
	if modelEP.Status != nil {
		if modelEP.Status.ExternalIdentifiers != nil {
			containerID = modelEP.Status.ExternalIdentifiers.ContainerID
			ns, podName = k8s.ParseNamespaceName(modelEP.Status.ExternalIdentifiers.PodName)
		}
		if modelEP.Status.Identity != nil {
			labels = modelEP.Status.Identity.Labels
			sort.Strings(labels)
		}
	}
	ep := &v1.Endpoint{
		ID:           uint64(modelEP.ID),
		PodName:      podName,
		PodNamespace: ns,
		Created:      time.Now(),
		Labels:       labels,
	}

	if containerID != "" {
		ep.ContainerIDs = []string{containerID}
	}
	if modelEP.Status != nil && modelEP.Status.Networking != nil {
		// Right now we assume the endpoint will only have one IPv4 and one IPv6
		for _, ip := range modelEP.Status.Networking.Addressing {
			if ipv4 := net.ParseIP(ip.IPV4).To4(); ipv4 != nil {
				ep.IPv4 = ipv4
			}
			if ipv6 := net.ParseIP(ip.IPV6).To16(); ipv6 != nil {
				ep.IPv6 = ipv6
			}
		}
	}

	return ep
}

// ParseEndpointFromEndpointDeleteNotification returns an endpoint parsed from
// the EndpointDeleteNotification.
func ParseEndpointFromEndpointDeleteNotification(edn monitorAPI.EndpointDeleteNotification) *v1.Endpoint {
	now := time.Now()
	return &v1.Endpoint{
		ID:           edn.ID,
		PodName:      edn.PodName,
		PodNamespace: edn.Namespace,
		Created:      time.Unix(0, 0),
		Deleted:      &now,
	}
}
