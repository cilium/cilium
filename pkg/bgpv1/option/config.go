// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package option

import "github.com/spf13/pflag"

const (
	// Enables advertising LoadBalancerIP routes with the BGP ORIGIN
	// attribute set to INCOMPLETE (2), matching MetalLB’s legacy behavior,
	// instead of the default IGP (0).
	EnableBGPLegacyOriginAttribute = "enable-bgp-legacy-origin-attribute"
)

type BGPConfig struct {
	// Enables LoadBalancerIP routes to be advertised with BGP Origin Attribute set to INCOMPLETE
	EnableBGPLegacyOriginAttribute bool
}

var DefaultConfig = BGPConfig{
	EnableBGPLegacyOriginAttribute: false,
}

func (def BGPConfig) Flags(flags *pflag.FlagSet) {
	flags.Bool(EnableBGPLegacyOriginAttribute, def.EnableBGPLegacyOriginAttribute, "Enable LoadBalancerIP routes to be advertised with BGP Origin Attribute set to INCOMPLETE")
}
