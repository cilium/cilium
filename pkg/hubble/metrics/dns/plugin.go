// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package dns

import (
	"github.com/cilium/cilium/pkg/hubble/metrics/api"
)

type dnsPlugin struct{}

func (p *dnsPlugin) NewHandler() api.Handler {
	return &dnsHandler{}
}

func (p *dnsPlugin) HelpText() string {
	return `dns - DNS related metrics
Reports metrics related to DNS queries and responses

Metrics:
  hubble_dns_queries_total    Number of observed TCP queries
  hubble_dns_responses_total  Number of observed TCP responses

Options:
 query                  - Include query name as label
 ignoreAAAA             - Do not include AAAA query & responses in metrics` +
		api.ContextOptionsHelp
}

func init() {
	api.DefaultRegistry().Register("dns", &dnsPlugin{})
}
