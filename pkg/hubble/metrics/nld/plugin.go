// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package nld

import (
	"github.com/cilium/cilium/pkg/hubble/metrics/api"
)

type nldPlugin struct{}

func (p *nldPlugin) NewHandler() api.Handler {
	return &nldHandler{}
}

func (p *nldPlugin) HelpText() string {
	return `nodelocaldns related metrics
Reports metrics related to DNS queries and responses focusing on NodeLocalDNS,
the caching layer.

Metrics:
  hubble_nld_downstream_total   Number of observed DNS queries to NLD
  hubble_nld_upstream_total     Number of observed DNS queries from NLD
  hubble_nld_bypass_total       Number of observed DNS queries bypassing NLD

Options:
 direction              - Include direction as label
 ignoreHost             - Exclude DNS traffic from the node/host` +
		api.ContextOptionsHelp
}

func init() {
	api.DefaultRegistry().Register("nld", &nldPlugin{})
}
