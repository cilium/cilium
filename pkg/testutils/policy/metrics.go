// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package testpolicy

import (
	"github.com/cilium/cilium/pkg/policy/types"
)

type policyMetricsNoop struct {
}

func (p *policyMetricsNoop) AddRule(types.PolicyEntry) {
}

func (p *policyMetricsNoop) DelRule(types.PolicyEntry) {
}

func NewPolicyMetricsNoop() types.PolicyMetrics {
	return &policyMetricsNoop{}
}
