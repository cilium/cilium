// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package config

import (
	"github.com/spf13/pflag"

	"github.com/cilium/cilium/pkg/option"
)

type RoutesConfig struct {
	BGPNoEndpointsRoutable bool
}

func (def RoutesConfig) Flags(flags *pflag.FlagSet) {
	flags.Bool(option.BGPNoEndpointsRoutable, def.BGPNoEndpointsRoutable, "Enable routes when service has 0 endpoints")
}

var DefaultRoutesConfig = RoutesConfig{
	BGPNoEndpointsRoutable: true,
}
