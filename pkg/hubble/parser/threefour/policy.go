// Copyright 2019 Authors of Hubble
// Copyright 2020 Authors of Cilium
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

package threefour

import (
	"strconv"

	"github.com/cilium/cilium/api/v1/flow"
	"github.com/cilium/cilium/pkg/k8s"
	slim_networkingv1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/networking/v1"
	"github.com/cilium/cilium/pkg/labels"
	monitorAPI "github.com/cilium/cilium/pkg/monitor/api"
	"github.com/cilium/cilium/pkg/policy/api"
)

func flowMatchesNetworkPolicy(fl *flow.Flow, policy *slim_networkingv1.NetworkPolicy) bool {
	rules, err := k8s.ParseNetworkPolicy(policy)
	if err != nil {
		return false
	}

	for _, rule := range rules {
		if flowMatchesRule(fl, rule) {
			return true
		}
	}

	return false
}

func flowMatchesRule(fl *flow.Flow, rule *api.Rule) bool {
	if fl.PolicyMatchType == monitorAPI.PolicyMatchAll {
		return true
	}

	var remote *flow.Endpoint
	l3 := make([]api.EndpointSelectorSlice, 0)
	l4 := make([]api.PortRule, 0)
	if fl.TrafficDirection == flow.TrafficDirection_EGRESS {
		remote = fl.Destination
		for _, eRule := range rule.Egress {
			l3 = append(l3, eRule.GetDestinationEndpointSelectorsWithRequirements(nil))
			l4 = append(l4, eRule.ToPorts...)
		}
	} else {
		remote = fl.Source
		for _, iRule := range rule.Ingress {
			l3 = append(l3, iRule.GetSourceEndpointSelectorsWithRequirements(nil))
			l4 = append(l4, iRule.ToPorts...)
		}
	}

	hasL3Match := endpointMatchesL3Selector(remote, l3)
	if fl.PolicyMatchType == monitorAPI.PolicyMatchL3Only {
		return hasL3Match
	}

	hasL4Match := flowMatchesL4Rule(fl, l4)
	if fl.PolicyMatchType == monitorAPI.PolicyMatchL4Only {
		return hasL4Match
	}

	return hasL3Match && hasL4Match
}

func endpointMatchesL3Selector(endpoint *flow.Endpoint, selectors []api.EndpointSelectorSlice) bool {
	lblArray := labels.NewSelectLabelArrayFromModel(endpoint.Labels)
	for _, selector := range selectors {
		if selector.SelectsAllEndpoints() || selector.Matches(lblArray) {
			return true
		}
	}

	return false
}

func flowMatchesL4Rule(fl *flow.Flow, rules []api.PortRule) bool {
	l4 := fl.L4
	port := uint32(0)
	proto := api.ProtoAny

	switch l4.GetProtocol().(type) {
	case *flow.Layer4_TCP:
		proto = api.ProtoTCP
		port = l4.GetTCP().DestinationPort
	case *flow.Layer4_UDP:
		proto = api.ProtoUDP
		port = l4.GetUDP().DestinationPort
	}

	portStr := strconv.Itoa(int(port))
	for _, rule := range rules {
		for _, p := range rule.Ports {
			portMatched := p.Port == portStr
			protoMatched := p.Protocol == "" ||
				p.Protocol == api.ProtoAny ||
				p.Protocol == proto

			if portMatched && protoMatched {
				return true
			}
		}
	}

	return false
}
