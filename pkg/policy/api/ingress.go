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

package api

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// IngressRule contains all rule types which can be applied at ingress,
// i.e. network traffic that originates outside of the endpoint and
// is entering the endpoint selected by the endpointSelector.
//
// - All members of this structure are optional. If omitted or empty, the
//   member will have no effect on the rule.
//
// - If multiple members are set, all of them need to match in order for
//   the rule to take effect. The exception to this rule is FromRequires field;
//   the effects of any Requires field in any rule will apply to all other
//   rules as well.
//
// - For now, combining ToPorts, FromCIDR, and FromEndpoints in the same rule
//   is not supported and any such rules will be rejected. In the future, this
//   will be supported and if multiple members of this structure are specified,
//   then all members must match in order for the rule to take effect. The
//   exception to this rule is the Requires field, the effects of any Requires
//   field in any rule will apply to all other rules as well.
type IngressRule struct {
	// FromEndpoints is a list of endpoints identified by an
	// EndpointSelector which are allowed to communicate with the endpoint
	// subject to the rule.
	//
	// Example:
	// Any endpoint with the label "role=backend" can be consumed by any
	// endpoint carrying the label "role=frontend".
	//
	// +optional
	FromEndpoints []EndpointSelector `json:"fromEndpoints,omitempty"`

	// FromRequires is a list of additional constraints which must be met
	// in order for the selected endpoints to be reachable. These
	// additional constraints do no by itself grant access privileges and
	// must always be accompanied with at least one matching FromEndpoints.
	//
	// Example:
	// Any Endpoint with the label "team=A" requires consuming endpoint
	// to also carry the label "team=A".
	//
	// +optional
	FromRequires []EndpointSelector `json:"fromRequires,omitempty"`

	// ToPorts is a list of destination ports identified by port number and
	// protocol which the endpoint subject to the rule is allowed to
	// receive connections on.
	//
	// Example:
	// Any endpoint with the label "app=httpd" can only accept incoming
	// connections on port 80/tcp.
	//
	// +optional
	ToPorts []PortRule `json:"toPorts,omitempty"`

	// FromCIDR is a list of IP blocks which the endpoint subject to the
	// rule is allowed to receive connections from. Only connections which
	// do *not* originate from the cluster or from the local host are subject
	// to CIDR rules. In order to allow in-cluster connectivity, use the
	// FromEndpoints field.  This will match on the source IP address of
	// incoming connections. Adding  a prefix into FromCIDR or into
	// FromCIDRSet with no ExcludeCIDRs is  equivalent.  Overlaps are
	// allowed between FromCIDR and FromCIDRSet.
	//
	// Example:
	// Any endpoint with the label "app=my-legacy-pet" is allowed to receive
	// connections from 10.3.9.1
	//
	// +optional
	FromCIDR CIDRSlice `json:"fromCIDR,omitempty"`

	// FromCIDRSet is a list of IP blocks which the endpoint subject to the
	// rule is allowed to receive connections from in addition to FromEndpoints,
	// along with a list of subnets contained within their corresponding IP block
	// from which traffic should not be allowed.
	// This will match on the source IP address of incoming connections. Adding
	// a prefix into FromCIDR or into FromCIDRSet with no ExcludeCIDRs is
	// equivalent. Overlaps are allowed between FromCIDR and FromCIDRSet.
	//
	// Example:
	// Any endpoint with the label "app=my-legacy-pet" is allowed to receive
	// connections from 10.0.0.0/8 except from IPs in subnet 10.96.0.0/12.
	//
	// +optional
	FromCIDRSet CIDRRuleSlice `json:"fromCIDRSet,omitempty"`

	// FromEntities is a list of special entities which the endpoint subject
	// to the rule is allowed to receive connections from. Supported entities are
	// `world`, `cluster` and `host`
	//
	// +optional
	FromEntities EntitySlice `json:"fromEntities,omitempty"`
}

// GetSourceEndpointSelectorsWithRequirements returns a slice of endpoints selectors covering
// all L3 source selectors of the ingress rule
func (i *IngressRule) GetSourceEndpointSelectorsWithRequirements(requirements []metav1.LabelSelectorRequirement) EndpointSelectorSlice {
	res := make(EndpointSelectorSlice, 0, len(i.FromEndpoints)+len(i.FromEntities)+len(i.FromCIDRSet)+len(i.FromCIDR))
	if len(requirements) > 0 && len(i.FromEndpoints) > 0 {
		for idx := range i.FromEndpoints {
			sel := *i.FromEndpoints[idx].DeepCopy()
			sel.MatchExpressions = append(sel.MatchExpressions, requirements...)
			sel.SyncRequirementsWithLabelSelector()
			res = append(res, sel)
		}
	} else {
		res = append(res, i.FromEndpoints...)
	}
	res = append(res, i.FromEntities.GetAsEndpointSelectors()...)
	res = append(res, i.FromCIDR.GetAsEndpointSelectors()...)
	res = append(res, i.FromCIDRSet.GetAsEndpointSelectors()...)

	return res
}

// IsLabelBased returns true whether the L3 source endpoints are selected based
// on labels, i.e. either by setting FromEndpoints or FromEntities, or not
// setting any From field.
func (i *IngressRule) IsLabelBased() bool {
	return len(i.FromRequires)+len(i.FromCIDR)+len(i.FromCIDRSet) == 0
}
