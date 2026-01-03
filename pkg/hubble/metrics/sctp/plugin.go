// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package sctp

import "github.com/cilium/cilium/pkg/hubble/metrics/api"

type sctpPlugin struct{}

func (p *sctpPlugin) NewHandler() api.Handler {
	return &sctpHandler{}
}

func (p *sctpPlugin) HelpText() string {
	return `sctp - SCTP metrics
Metrics related to the SCTP protocol

Metrics:
  hubble_sctp_flags_total - Distribution of SCTP Chunk Type

Options:` +
		api.ContextOptionsHelp
}

func init() {
	api.DefaultRegistry().Register("sctp", &sctpPlugin{})
}
