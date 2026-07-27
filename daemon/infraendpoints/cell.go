// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package infraendpoints

import (
	"github.com/cilium/hive/cell"
	"github.com/spf13/pflag"
)

// Cell is responsible to initialize the Cilium Agent "infrastructure"
// (host, health, ingress) endpoints. This includes IP allocation and
// setting up the endpoint.
var Cell = cell.Module(
	"agent-infra-endpoints",
	"Cilium Agent infrastructure endpoints",

	cell.Config(config{
		ServiceLoopbackIPv4: "169.254.42.1",
		ServiceLoopbackIPv6: "fe80::1",
	}),
	cell.Provide(newInfraIPAllocator),
	cell.Invoke(registerIngressEndpoint),
	cell.Invoke(registerHostEndpoint),
)

type config struct {
	ServiceLoopbackIPv4 string `mapstructure:"ipv4-service-loopback-address"`
	ServiceLoopbackIPv6 string `mapstructure:"ipv6-service-loopback-address"`
}

func (r config) Flags(flags *pflag.FlagSet) {
	flags.String("ipv4-service-loopback-address", r.ServiceLoopbackIPv4, "IPv4 source address to use for SNAT when a Pod talks to itself over a Service.")
	flags.String("ipv6-service-loopback-address", r.ServiceLoopbackIPv6, "IPv6 source address to use for SNAT when a Pod talks to itself over a Service.")
}
