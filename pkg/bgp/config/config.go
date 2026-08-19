// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package config

import "github.com/spf13/pflag"

const (
	// Enables advertising LoadBalancerIP routes with the BGP ORIGIN
	// attribute set to INCOMPLETE (2), matching MetalLB’s legacy behavior,
	// instead of the default IGP (0).
	EnableBGPLegacyOriginAttribute = "enable-bgp-legacy-origin-attribute"
)

type BGPConfig struct {
	// Enables LoadBalancerIP routes to be advertised with BGP Origin Attribute set to INCOMPLETE
	EnableLegacyOriginAttribute bool `mapstructure:"enable-bgp-legacy-origin-attribute"`
}

var DefaultConfig = BGPConfig{
	EnableLegacyOriginAttribute: false,
}

func (def BGPConfig) Flags(flags *pflag.FlagSet) {
	flags.Bool(EnableBGPLegacyOriginAttribute, def.EnableLegacyOriginAttribute, "Enable LoadBalancerIP routes to be advertised with BGP Origin Attribute set to INCOMPLETE")
}
