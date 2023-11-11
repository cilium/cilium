// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package filters

import (
	"slices"

	"github.com/cilium/cilium-cli/connectivity/filters"
	"github.com/cilium/cilium/api/v1/flow"
	"github.com/cilium/cilium/pkg/monitor/api"
)

// PolicyVerdict matches on policy verdict events.
func PolicyVerdict(opts ...PolicyVerdictOption) filters.FlowFilterImplementation {
	f := &policyVerdictFilter{}
	for _, fn := range opts {
		f = fn(f)
	}
	return f
}

type policyVerdictFilter struct {
	ingressAllowedBy []flow.Policy
	egressAllowedBy  []flow.Policy
}

type PolicyVerdictOption func(filter *policyVerdictFilter) *policyVerdictFilter

func WithIngressAllowedBy(policies []flow.Policy) PolicyVerdictOption {
	return func(f *policyVerdictFilter) *policyVerdictFilter {
		f.ingressAllowedBy = policies
		return f
	}
}

func WithEgressAllowedBy(policies []flow.Policy) PolicyVerdictOption {
	return func(f *policyVerdictFilter) *policyVerdictFilter {
		f.egressAllowedBy = policies
		return f
	}
}

func (p policyVerdictFilter) Match(f *flow.Flow, _ *filters.FlowContext) bool {
	if f.GetEventType().Type != api.MessageTypePolicyVerdict ||
		len(p.egressAllowedBy) != len(f.EgressAllowedBy) ||
		len(p.ingressAllowedBy) != len(f.IngressAllowedBy) {
		return false
	}
	for i := 0; i < len(p.ingressAllowedBy); i++ {
		if p.ingressAllowedBy[i].Namespace != f.IngressAllowedBy[i].Namespace ||
			p.ingressAllowedBy[i].Name != f.IngressAllowedBy[i].Name ||
			!slices.Equal(p.ingressAllowedBy[i].Labels, f.IngressAllowedBy[i].Labels) {
			return false
		}
	}
	for i := 0; i < len(p.egressAllowedBy); i++ {
		if p.egressAllowedBy[i].Namespace != f.EgressAllowedBy[i].Namespace ||
			p.egressAllowedBy[i].Name != f.EgressAllowedBy[i].Name ||
			!slices.Equal(p.egressAllowedBy[i].Labels, f.EgressAllowedBy[i].Labels) {
			return false
		}
	}
	return true
}

func (p policyVerdictFilter) String(fc *filters.FlowContext) string {
	return "policy-verdict"
}
