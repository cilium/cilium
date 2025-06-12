// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package testpolicy

import (
	"github.com/cilium/cilium/pkg/policy/api"
	"github.com/cilium/cilium/pkg/policy/types"
)

type policyMetricsNoop struct {
}

func (p *policyMetricsNoop) AddRule(api.Rule) {
}

func (p *policyMetricsNoop) DelRule(api.Rule) {
}

func NewPolicyMetricsNoop() types.PolicyMetrics {
	return &policyMetricsNoop{}
}
