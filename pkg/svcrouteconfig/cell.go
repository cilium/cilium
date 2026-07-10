// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package svcrouteconfig

import (
	"github.com/cilium/hive/cell"
	"github.com/spf13/pflag"
)

var Cell = cell.Module(
	"service-route-config",
	"Service route configuration",

	cell.Config(DefaultConfig),
)

type RoutesConfig struct {
	EnableNoServiceEndpointsRoutable bool
}

var DefaultConfig = RoutesConfig{
	EnableNoServiceEndpointsRoutable: true,
}

func (def RoutesConfig) Flags(flags *pflag.FlagSet) {
	flags.Bool("enable-no-service-endpoints-routable", def.EnableNoServiceEndpointsRoutable, "Enable routes when service has 0 endpoints")
}
