// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package types

import "github.com/cilium/cilium/pkg/policy/api"

type PolicyMetrics interface {
	AddRule(r api.Rule)
	DelRule(r api.Rule)
}

type policyMetricsNoop struct {
}

func (p *policyMetricsNoop) AddRule(api.Rule) {
}

func (p *policyMetricsNoop) DelRule(api.Rule) {
}

func NewPolicyMetricsNoop() PolicyMetrics {
	return &policyMetricsNoop{}
}
