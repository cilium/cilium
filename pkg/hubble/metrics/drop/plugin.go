// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package drop

import (
	"github.com/cilium/cilium/pkg/hubble/metrics/api"
)

type dropPlugin struct{}

func (p *dropPlugin) NewHandler() api.Handler {
	return &dropHandler{}
}

func (p *dropPlugin) HelpText() string {
	return `drop - Drop metrics
Reports metrics related to drops.

Metrics:
  hubble_drop_total  Number of dropped packets

Options:` +
		api.ContextOptionsHelp
}

func init() {
	api.DefaultRegistry().Register("drop", &dropPlugin{})
}
