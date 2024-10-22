// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package flows_to_world

import (
	"github.com/cilium/cilium/pkg/hubble/metrics/api"
)

type flowsToWorldPlugin struct{}

func (p *flowsToWorldPlugin) NewHandler() api.Handler {
	return &flowsToWorldHandler{}
}

func (p *flowsToWorldPlugin) HelpText() string {
	return `flows-to-world - External flow metrics
Reports metrics related to flows to reserved:world.

Metrics:
  hubble_flows_to_world_total  Number of flows to reserved:world.

Options:
 any-drop - By default, this metric counts dropped flows if and only
            if the drop_reason is "Policy denied". Set this option to
            count any dropped flows to reserved:world.
 port     - Include destination port as a label.
 syn-only - Only count non-reply SYNs for TCP flows.` +
		api.ContextOptionsHelp
}

func init() {
	api.DefaultRegistry().Register("flows-to-world", &flowsToWorldPlugin{})
}
