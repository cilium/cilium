// SPDX-License-Identifier: Apache-2.0
// Copyright 2016-2021 Authors of Cilium

package api

import (
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
)

// IngressCommonRule is a rule that shares some of its fields across the
// IngressRule and IngressDenyRule. It's publicly exported so the code
// generators can generate code for this structure.
type IngressCommonRule struct {
	// FromEndpoints is a list of endpoints identified by an
	// EndpointSelector which are allowed to communicate with the endpoint
	// subject to the rule.
	//
	// Example:
	// Any endpoint with the label "role=backend" can be consumed by any
	// endpoint carrying the label "role=frontend".
	//
	// +kubebuilder:validation:Optional
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
	// +kubebuilder:validation:Optional
	FromRequires []EndpointSelector `json:"fromRequires,omitempty"`

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
	// +kubebuilder:validation:Optional
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
	// +kubebuilder:validation:Optional
	FromCIDRSet CIDRRuleSlice `json:"fromCIDRSet,omitempty"`

	// FromEntities is a list of special entities which the endpoint subject
	// to the rule is allowed to receive connections from. Supported entities are
	// `world`, `cluster` and `host`
	//
	// +kubebuilder:validation:Optional
	FromEntities EntitySlice `json:"fromEntities,omitempty"`

	// TODO: Move this to the policy package
	// (https://github.com/cilium/cilium/issues/8353)
	aggregatedSelectors EndpointSelectorSlice `json:"-"`
}

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
// - FromEndpoints, FromCIDR, FromCIDRSet and FromEntities are mutually
//   exclusive. Only one of these members may be present within an individual
//   rule.
type IngressRule struct {
	IngressCommonRule `json:",inline"`

	// ToPorts is a list of destination ports identified by port number and
	// protocol which the endpoint subject to the rule is allowed to
	// receive connections on.
	//
	// Example:
	// Any endpoint with the label "app=httpd" can only accept incoming
	// connections on port 80/tcp.
	//
	// +kubebuilder:validation:Optional
	ToPorts PortRules `json:"toPorts,omitempty"`

	// ICMPs is a list of ICMP rule identified by type number
	// which the endpoint subject to the rule is allowed to
	// receive connections on.
	//
	// Example:
	// Any endpoint with the label "app=httpd" can only accept incoming
	// type 8 ICMP connections.
	//
	// +kubebuilder:validation:Optional
	ICMPs ICMPRules `json:"icmps,omitempty"`
}

// IngressDenyRule contains all rule types which can be applied at ingress,
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
// - FromEndpoints, FromCIDR, FromCIDRSet and FromEntities are mutually
//   exclusive. Only one of these members may be present within an individual
//   rule.
type IngressDenyRule struct {
	IngressCommonRule `json:",inline"`

	// ToPorts is a list of destination ports identified by port number and
	// protocol which the endpoint subject to the rule is not allowed to
	// receive connections on.
	//
	// Example:
	// Any endpoint with the label "app=httpd" can not accept incoming
	// connections on port 80/tcp.
	//
	// +kubebuilder:validation:Optional
	ToPorts PortDenyRules `json:"toPorts,omitempty"`

	// ICMPs is a list of ICMP rule identified by type number
	// which the endpoint subject to the rule is not allowed to
	// receive connections on.
	//
	// Example:
	// Any endpoint with the label "app=httpd" can not accept incoming
	// type 8 ICMP connections.
	//
	// +kubebuilder:validation:Optional
	ICMPs ICMPRules `json:"icmps,omitempty"`
}

// SetAggregatedSelectors creates a single slice containing all of the following
// fields within the IngressRule, converted to EndpointSelector, to be stored
// within the IngressRule for easy lookup while performing policy evaluation
// for the rule:
// * FromEntities
// * FromCIDR
// * FromCIDRSet
//
// FromEndpoints is not aggregated due to requirement folding in
// GetSourceEndpointSelectorsWithRequirements()
func (i *IngressCommonRule) SetAggregatedSelectors() {
	res := make(EndpointSelectorSlice, 0, len(i.FromEntities)+len(i.FromCIDR)+len(i.FromCIDRSet))
	res = append(res, i.FromEntities.GetAsEndpointSelectors()...)
	res = append(res, i.FromCIDR.GetAsEndpointSelectors()...)
	res = append(res, i.FromCIDRSet.GetAsEndpointSelectors()...)
	// Goroutines can race setting this, but they will all compute
	// the same result, so it does not matter.
	i.aggregatedSelectors = res
}

// GetSourceEndpointSelectorsWithRequirements returns a slice of endpoints selectors covering
// all L3 source selectors of the ingress rule
func (i *IngressCommonRule) GetSourceEndpointSelectorsWithRequirements(requirements []slim_metav1.LabelSelectorRequirement) EndpointSelectorSlice {
	if i.aggregatedSelectors == nil {
		i.SetAggregatedSelectors()
	}
	res := make(EndpointSelectorSlice, 0, len(i.FromEndpoints)+len(i.aggregatedSelectors))
	if len(requirements) > 0 && len(i.FromEndpoints) > 0 {
		for idx := range i.FromEndpoints {
			sel := *i.FromEndpoints[idx].DeepCopy()
			sel.MatchExpressions = append(sel.MatchExpressions, requirements...)
			sel.SyncRequirementsWithLabelSelector()
			// Even though this string is deep copied, we need to override it
			// because we are updating the contents of the MatchExpressions.
			sel.cachedLabelSelectorString = sel.LabelSelector.String()
			res = append(res, sel)
		}
	} else {
		res = append(res, i.FromEndpoints...)
	}

	return append(res, i.aggregatedSelectors...)
}

// AllowsWildcarding returns true if wildcarding should be performed upon
// policy evaluation for the given rule.
func (i *IngressCommonRule) AllowsWildcarding() bool {
	return len(i.FromRequires) == 0
}
