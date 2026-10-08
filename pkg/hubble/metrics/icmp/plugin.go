// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package icmp

import (
	"github.com/cilium/cilium/pkg/hubble/metrics/api"
)

type icmpPlugin struct{}

func (p *icmpPlugin) NewHandler() api.Handler {
	return &icmpHandler{}
}

func (p *icmpPlugin) HelpText() string {
	return `icmp - icmp metrics
Reports metrics related to the Internet Control Message Protocol (ICMP) such as
message counts.

Metrics:
  hubble_icmp_total  Number of ICMP messages by prorocol family and type

Options:` +
		api.ContextOptionsHelp
}

func init() {
	api.DefaultRegistry().Register("icmp", &icmpPlugin{})
}
