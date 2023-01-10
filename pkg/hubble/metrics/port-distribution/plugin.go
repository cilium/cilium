// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package portdistribution

import (
	"github.com/cilium/cilium/pkg/hubble/metrics/api"
)

type portDistributionPlugin struct{}

func (p *portDistributionPlugin) NewHandler() api.Handler {
	return &portDistributionHandler{}
}

func (p *portDistributionPlugin) HelpText() string {
	return `port-distribution - Port distribution metrics
Reports metrics related to port distribution

Metrics:
  hubble_port_distribution_total  Number of packets by destination port number

Options:` +
		api.ContextOptionsHelp
}

func init() {
	api.DefaultRegistry().Register("port-distribution", &portDistributionPlugin{})
}
