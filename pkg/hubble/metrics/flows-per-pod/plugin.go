// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package flows_per_pod

import (
	"github.com/cilium/cilium/pkg/hubble/metrics/api"
)

type flowsPerPodPlugin struct{}

func (p *flowsPerPodPlugin) NewHandler() api.Handler {
	return &flowsPerPodHandler{}
}

func (p *flowsPerPodPlugin) HelpText() string {
	return `flows-per-pod - Flows per pod
Reports metrics related to flows by pod

Metrics:
  hubble_flows_per_pod_total  Number of flows per pod

Options:` +
		api.ContextOptionsHelp
}

func init() {
	api.DefaultRegistry().Register("flows-per-pod", &flowsPerPodPlugin{})
}
