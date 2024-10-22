// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package tcp

import (
	"github.com/cilium/cilium/pkg/hubble/metrics/api"
)

type tcpPlugin struct{}

func (p *tcpPlugin) NewHandler() api.Handler {
	return &tcpHandler{}
}

func (p *tcpPlugin) HelpText() string {
	return `tcp - TCP metrics
Metrics related to the TCP protocol

Metrics:
  hubble_tcp_flags_total - Distribution of TCP flags

Options:` +
		api.ContextOptionsHelp
}

func init() {
	api.DefaultRegistry().Register("tcp", &tcpPlugin{})
}
