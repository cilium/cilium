// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package flow

import (
	"github.com/cilium/cilium/pkg/hubble/metrics/api"
)

type flowPlugin struct{}

func (p *flowPlugin) NewHandler() api.Handler {
	return &flowHandler{}
}

func (p *flowPlugin) HelpText() string {
	return `flow - Generic flow metrics
Reports metrics related to flow processing

Metrics:
  hubble_flows_processed_total  Number of flows processed

Options:` +
		api.ContextOptionsHelp
}

func init() {
	api.DefaultRegistry().Register("flow", &flowPlugin{})
}
