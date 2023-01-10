// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package api

import (
	"context"
	"encoding/json"

	"github.com/cilium/cilium/pkg/labels"
)

// AuthType is a string identifying a supported authentication type
type AuthType string

const (
	AuthTypeNull AuthType = "null" // Always succeeds
)

// Auth specifies the kind of cryptographic authentication required for the traffic to
// be allowed.
type Auth struct {
	// Type is the required authentication type for the allowed traffic, if any.
	//
	// +kubebuilder:validation:Enum=null
	// +kubebuilder:validation:Required
	Type AuthType `json:"type"`
}

// +kubebuilder:validation:Type=object

// Rule is a policy rule which must be applied to all endpoints which match the
// labels contained in the endpointSelector
//
// Each rule is split into an ingress section which contains all rules
// applicable at ingress, and an egress section applicable at egress. For rule
// types such as `L4Rule` and `CIDR` which can be applied at both ingress and
// egress, both ingress and egress side have to either specifically allow the
// connection or one side has to be omitted.
//
// Either ingress, egress, or both can be provided. If both ingress and egress
// are omitted, the rule has no effect.
//
// +deepequal-gen:private-method=true
type Rule struct {
	// EndpointSelector selects all endpoints which should be subject to
	// this rule. EndpointSelector and NodeSelector cannot be both empty and
	// are mutually exclusive.
	//
	// +kubebuilder:validation:OneOf
	EndpointSelector EndpointSelector `json:"endpointSelector,omitempty"`

	// NodeSelector selects all nodes which should be subject to this rule.
	// EndpointSelector and NodeSelector cannot be both empty and are mutually
	// exclusive. Can only be used in CiliumClusterwideNetworkPolicies.
	//
	// +kubebuilder:validation:OneOf
	NodeSelector EndpointSelector `json:"nodeSelector,omitempty"`

	// Ingress is a list of IngressRule which are enforced at ingress.
	// If omitted or empty, this rule does not apply at ingress.
	//
	// +kubebuilder:validation:Optional
	Ingress []IngressRule `json:"ingress,omitempty"`

	// IngressDeny is a list of IngressDenyRule which are enforced at ingress.
	// Any rule inserted here will by denied regardless of the allowed ingress
	// rules in the 'ingress' field.
	// If omitted or empty, this rule does not apply at ingress.
	//
	// +kubebuilder:validation:Optional
	IngressDeny []IngressDenyRule `json:"ingressDeny,omitempty"`

	// Egress is a list of EgressRule which are enforced at egress.
	// If omitted or empty, this rule does not apply at egress.
	//
	// +kubebuilder:validation:Optional
	Egress []EgressRule `json:"egress,omitempty"`

	// EgressDeny is a list of EgressDenyRule which are enforced at egress.
	// Any rule inserted here will by denied regardless of the allowed egress
	// rules in the 'egress' field.
	// If omitted or empty, this rule does not apply at egress.
	//
	// +kubebuilder:validation:Optional
	EgressDeny []EgressDenyRule `json:"egressDeny,omitempty"`

	// Labels is a list of optional strings which can be used to
	// re-identify the rule or to store metadata. It is possible to lookup
	// or delete strings based on labels. Labels are not required to be
	// unique, multiple rules can have overlapping or identical labels.
	//
	// +kubebuilder:validation:Optional
	Labels labels.LabelArray `json:"labels,omitempty"`

	// Description is a free form string, it can be used by the creator of
	// the rule to store human readable explanation of the purpose of this
	// rule. Rules cannot be identified by comment.
	//
	// +kubebuilder:validation:Optional
	Description string `json:"description,omitempty"`
}

// MarshalJSON returns the JSON encoding of Rule r. We need to overwrite it to
// enforce omitempty on the EndpointSelector nested structures.
func (r *Rule) MarshalJSON() ([]byte, error) {
	type common struct {
		Ingress     []IngressRule     `json:"ingress,omitempty"`
		IngressDeny []IngressDenyRule `json:"ingressDeny,omitempty"`
		Egress      []EgressRule      `json:"egress,omitempty"`
		EgressDeny  []EgressDenyRule  `json:"egressDeny,omitempty"`
		Labels      labels.LabelArray `json:"labels,omitempty"`
		Description string            `json:"description,omitempty"`
	}

	var a interface{}
	ruleCommon := common{
		Ingress:     r.Ingress,
		IngressDeny: r.IngressDeny,
		Egress:      r.Egress,
		EgressDeny:  r.EgressDeny,
		Labels:      r.Labels,
		Description: r.Description,
	}

	// Only one of endpointSelector or nodeSelector is permitted.
	switch {
	case r.EndpointSelector.LabelSelector != nil:
		a = struct {
			EndpointSelector EndpointSelector `json:"endpointSelector,omitempty"`
			common
		}{
			EndpointSelector: r.EndpointSelector,
			common:           ruleCommon,
		}
	case r.NodeSelector.LabelSelector != nil:
		a = struct {
			NodeSelector EndpointSelector `json:"nodeSelector,omitempty"`
			common
		}{
			NodeSelector: r.NodeSelector,
			common:       ruleCommon,
		}
	}

	return json.Marshal(a)
}

func (r *Rule) DeepEqual(o *Rule) bool {
	switch {
	case (r == nil) != (o == nil):
		return false
	case (r == nil) && (o == nil):
		return true
	}
	return r.deepEqual(o)
}

// NewRule builds a new rule with no selector and no policy.
func NewRule() *Rule {
	return &Rule{}
}

// WithEndpointSelector configures the Rule with the specified selector.
func (r *Rule) WithEndpointSelector(es EndpointSelector) *Rule {
	r.EndpointSelector = es
	return r
}

// WithIngressRules configures the Rule with the specified rules.
func (r *Rule) WithIngressRules(rules []IngressRule) *Rule {
	r.Ingress = rules
	return r
}

// WithIngressDenyRules configures the Rule with the specified rules.
func (r *Rule) WithIngressDenyRules(rules []IngressDenyRule) *Rule {
	r.IngressDeny = rules
	return r
}

// WithEgressRules configures the Rule with the specified rules.
func (r *Rule) WithEgressRules(rules []EgressRule) *Rule {
	r.Egress = rules
	return r
}

// WithEgressDenyRules configures the Rule with the specified rules.
func (r *Rule) WithEgressDenyRules(rules []EgressDenyRule) *Rule {
	r.EgressDeny = rules
	return r
}

// WithLabels configures the Rule with the specified labels metadata.
func (r *Rule) WithLabels(labels labels.LabelArray) *Rule {
	r.Labels = labels
	return r
}

// WithDescription configures the Rule with the specified description metadata.
func (r *Rule) WithDescription(desc string) *Rule {
	r.Description = desc
	return r
}

// RequiresDerivative it return true if the rule has a derivative rule.
func (r *Rule) RequiresDerivative() bool {
	for _, rule := range r.Egress {
		if rule.RequiresDerivative() {
			return true
		}
	}
	return false
}

// CreateDerivative will return a new Rule with the new data based gather
// by the rules that autogenerated new Rule
func (r *Rule) CreateDerivative(ctx context.Context) (*Rule, error) {
	newRule := r.DeepCopy()
	newRule.Egress = []EgressRule{}

	for _, egressRule := range r.Egress {
		derivativeEgressRule, err := egressRule.CreateDerivative(ctx)
		if err != nil {
			return newRule, err
		}
		newRule.Egress = append(newRule.Egress, *derivativeEgressRule)
	}
	return newRule, nil
}
