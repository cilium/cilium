// Copyright 2019 Authors of Hubble
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package dns

import (
	"github.com/cilium/hubble/pkg/metrics/api"
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
