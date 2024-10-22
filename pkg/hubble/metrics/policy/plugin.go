// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package policy

import (
	"github.com/cilium/cilium/pkg/hubble/metrics/api"
)

type policyPlugin struct{}

func (p *policyPlugin) NewHandler() api.Handler {
	return &policyHandler{}
}

func (p *policyPlugin) HelpText() string {
	return `policy - Policy metrics
Reports metrics related to Cilium network policies.

Metrics:
  hubble_policy_verdicts_total Total number of policy verdict events

Options:` +
		api.ContextOptionsHelp
}

func init() {
	api.DefaultRegistry().Register("policy", &policyPlugin{})
}
