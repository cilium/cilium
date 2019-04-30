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

// EgressRule contains all rule types which can be applied at egress, i.e.
// network traffic that originates inside the endpoint and exits the endpoint
// selected by the endpointSelector.
//
// - All members of this structure are optional. If omitted or empty, the
//   member will have no effect on the rule.
//
// - For now, combining ToPorts and ToCIDR in the same rule is not supported
//   and such rules will be rejected. In the future, this will be supported and
//   if if multiple members of the structure are specified, then all members
//   must match in order for the rule to take effect.
type EgressRule struct {
	// ToEndpoints is a list of endpoints identified by an EndpointSelector to
	// which the endpoints subject to the rule are allowed to communicate.
	//
	// Example:
	// Any endpoint with the label "role=frontend" can communicate with any
	// endpoint carrying the label "role=backend".
	//
	// +optional
	ToEndpoints []EndpointSelector `json:"toEndpoints,omitempty"`

	// ToRequires is a list of additional constraints which must be met
	// in order for the selected endpoints to be able to connect to other
	// endpoints. These additional constraints do no by itself grant access
	// privileges and must always be accompanied with at least one matching
	// ToEndpoints.
	//
	// Example:
	// Any Endpoint with the label "team=A" requires any endpoint to which it
	// communicates to also carry the label "team=A".
	//
	// +optional
	ToRequires []EndpointSelector `json:"toRequires,omitempty"`

	// ToPorts is a list of destination ports identified by port number and
	// protocol which the endpoint subject to the rule is allowed to
	// connect to.
	//
	// Example:
	// Any endpoint with the label "role=frontend" is allowed to initiate
	// connections to destination port 8080/tcp
	//
	// +optional
	ToPorts []PortRule `json:"toPorts,omitempty"`

	// ToCIDR is a list of IP blocks which the endpoint subject to the rule
	// is allowed to initiate connections. Only connections destined for
	// outside of the cluster and not targeting the host will be subject
	// to CIDR rules.  This will match on the destination IP address of
	// outgoing connections. Adding a prefix into ToCIDR or into ToCIDRSet
	// with no ExcludeCIDRs is equivalent. Overlaps are allowed between
	// ToCIDR and ToCIDRSet.
	//
	// Example:
	// Any endpoint with the label "app=database-proxy" is allowed to
	// initiate connections to 10.2.3.0/24
	//
	// +optional
	ToCIDR CIDRSlice `json:"toCIDR,omitempty"`

	// ToCIDRSet is a list of IP blocks which the endpoint subject to the rule
	// is allowed to initiate connections to in addition to connections
	// which are allowed via ToEndpoints, along with a list of subnets contained
	// within their corresponding IP block to which traffic should not be
	// allowed. This will match on the destination IP address of outgoing
	// connections. Adding a prefix into ToCIDR or into ToCIDRSet with no
	// ExcludeCIDRs is equivalent. Overlaps are allowed between ToCIDR and
	// ToCIDRSet.
	//
	// Example:
	// Any endpoint with the label "app=database-proxy" is allowed to
	// initiate connections to 10.2.3.0/24 except from IPs in subnet 10.2.3.0/28.
	//
	// +optional
	ToCIDRSet CIDRRuleSlice `json:"toCIDRSet,omitempty"`

	// ToEntities is a list of special entities to which the endpoint subject
	// to the rule is allowed to initiate connections. Supported entities are
	// `world`, `cluster` and `host`
	//
	// +optional
	ToEntities EntitySlice `json:"toEntities,omitempty"`

	// ToServices is a list of services to which the endpoint subject
	// to the rule is allowed to initiate connections.
	//
	// Example:
	// Any endpoint with the label "app=backend-app" is allowed to
	// initiate connections to all cidrs backing the "external-service" service
	// + optional
	ToServices []Service `json:"toServices,omitempty"`

	// ToFQDN allows whitelisting DNS names in place of IPs. The IPs that result
	// from DNS resolution of `ToFQDN.MatchName`s are added to the same
	// EgressRule object as ToCIDRSet entries, and behave accordingly. Any L4 and
	// L7 rules within this EgressRule will also apply to these IPs.
	// The DNS -> IP mapping is re-resolved periodically from within the
	// cilium-agent, and the IPs in the DNS response are effected in the policy
	// for selected pods as-is (i.e. the list of IPs is not modified in any way).
	// Note: An explicit rule to allow for DNS traffic is needed for the pods, as
	// ToFQDN counts as an egress rule and will enforce egress policy when
	// PolicyEnforcment=default.
	// Note: If the resolved IPs are IPs within the kubernetes cluster, the
	// ToFQDN rule will not apply to that IP.
	// Note: ToFQDN cannot occur in the same policy as other To* rules.
	//
	// The current implementation has a number of limitations:
	// - The DNS resolution originates from cilium-agent, and not from the pods.
	// Differences between the responses seen by cilium agent and a particular
	// pod will whitelist the incorrect IP.
	// - DNS TTLs are ignored, and cilium-agent will repoll on a short interval
	// (5 seconds). Each change to the DNS data will trigger a policy
	// regeneration. This may result in delayed updates to the policy for an
	// endpoint when the data changes often or the system is under load.
	//
	// +optional
	ToFQDNs FQDNSelectorSlice `json:"toFQDNs,omitempty"`

	// ToGroups is a directive that allows the integration with multiple outside
	// providers. Currently, only AWS is supported, and the rule can select by
	// multiple sub directives:
	//
	// Example:
	// toGroups:
	// - aws:
	//     securityGroupsIds:
	//     - 'sg-XXXXXXXXXXXXX'
	// +optional
	ToGroups []ToGroups `json:"toGroups,omitempty"`

	aggregatedSelectors EndpointSelectorSlice
}

// SetAggregatedSelectors creates a single slice containing all of the following
// fields within the EgressRule, converted to EndpointSelector, to be stored
// within the EgressRule for easy lookup while performing policy evaluation
// for the rule:
// * ToEndpoints
// * ToEntities
// * ToCIDR
// * ToCIDRSet
// * ToFQDNs
func (e *EgressRule) SetAggregatedSelectors() {
	res := make(EndpointSelectorSlice, 0, len(e.ToCIDR)+len(e.ToFQDNs)+len(e.ToCIDRSet)+len(e.ToEndpoints)+len(e.ToEntities))
	res = append(res, e.ToEndpoints...)
	res = append(res, e.ToEntities.GetAsEndpointSelectors()...)
	res = append(res, e.ToCIDR.GetAsEndpointSelectors()...)
	res = append(res, e.ToCIDRSet.GetAsEndpointSelectors()...)
	res = append(res, e.ToFQDNs.GetAsEndpointSelectors()...)
	e.aggregatedSelectors = res
}

// GetDestinationEndpointSelectors returns a slice of endpoints selectors
// covering all L3 destination selectors of the egress rule
func (e *EgressRule) GetDestinationEndpointSelectors() EndpointSelectorSlice {
	if e.aggregatedSelectors == nil {
		e.SetAggregatedSelectors()
	}
	return e.aggregatedSelectors
}

// GetDestinationEndpointSelectorsWithRequirements returns a slice of endpoints selectors covering
// all L3 source selectors of the ingress rule
func (e *EgressRule) GetDestinationEndpointSelectorsWithRequirements(requirements []metav1.LabelSelectorRequirement) EndpointSelectorSlice {
	res := make(EndpointSelectorSlice, 0, len(e.ToCIDR)+len(e.ToFQDNs)+len(e.ToCIDRSet)+len(e.ToEndpoints)+len(e.ToEntities))

	if len(requirements) > 0 && len(e.ToEndpoints) > 0 {
		for idx := range e.ToEndpoints {
			sel := *e.ToEndpoints[idx].DeepCopy()
			sel.MatchExpressions = append(sel.MatchExpressions, requirements...)
			sel.SyncRequirementsWithLabelSelector()
			res = append(res, sel)
		}
	} else {
		res = append(res, e.ToEndpoints...)
	}
	res = append(res, e.ToEntities.GetAsEndpointSelectors()...)
	res = append(res, e.ToCIDR.GetAsEndpointSelectors()...)
	res = append(res, e.ToCIDRSet.GetAsEndpointSelectors()...)
	res = append(res, e.ToFQDNs.GetAsEndpointSelectors()...)

	return res
}

// IsLabelBased returns true whether the L3 destination endpoints are selected
// based on labels, i.e. either by setting ToEndpoints or ToEntities, or not
// setting any To field.
func (e *EgressRule) IsLabelBased() bool {
	return len(e.ToRequires)+len(e.ToCIDR)+len(e.ToCIDRSet)+len(e.ToServices)+len(e.ToFQDNs) == 0
}

// RequiresDerivative returns true when the EgressRule contains sections that
// need a derivative policy created in order to be enforced (e.g. ToGroups).
func (e *EgressRule) RequiresDerivative() bool {
	return len(e.ToGroups) > 0
}

// CreateDerivative will return a new rule based on the data gathered by the
// rules that creates a new derivative policy.
// In the case of ToGroups will call outside using the groups callback and this
// function can take a bit of time.
func (e *EgressRule) CreateDerivative() (*EgressRule, error) {
	newRule := e.DeepCopy()
	if !e.RequiresDerivative() {
		return newRule, nil
	}
	newRule.ToCIDRSet = CIDRRuleSlice{}
	for _, group := range e.ToGroups {
		cidrSet, err := group.GetCidrSet()
		if err != nil {
			return &EgressRule{}, err
		}
		if len(cidrSet) == 0 {
			return &EgressRule{}, nil
		}
		newRule.ToCIDRSet = append(e.ToCIDRSet, cidrSet...)
	}
	newRule.ToGroups = nil
	e.SetAggregatedSelectors()
	return newRule, nil
}
