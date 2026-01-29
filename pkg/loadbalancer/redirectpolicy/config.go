// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package redirectpolicy

import (
	"net/netip"

	"github.com/spf13/pflag"
)

const (
	AddressMatcherCIDRsName = "lrp-address-matcher-cidrs"
	ToIPRangeName           = "lrp-to-ip-range"
)

type Config struct {
	// AddressMatcherCIDRs limits which addresses can be used in a
	// AddressMatcher rule to specific CIDRs. This allows global control over
	// what addresses can be matched over the namespaced CiliumLocalRedirectPolicies.
	AddressMatcherCIDRs []netip.Prefix `mapstructure:"lrp-address-matcher-cidrs"`
	// ToIPRange limits which IP addresses can be used in a ToIP rule to a specific range.
	// This is to prevent users to use LRP to access arbitrary IPs
	ToIPRange netip.Prefix `mapstructure:"lrp-to-ip-range"`
}

func (def Config) Flags(flags *pflag.FlagSet) {
	flags.StringSlice(AddressMatcherCIDRsName, []string{}, "Limit address matches to specific CIDRs")
	flags.String(ToIPRangeName, def.ToIPRange.String(), "Limit ToIP matches to specific IP range")
}

func (cfg Config) addressAllowed(addr netip.Addr) bool {
	if len(cfg.AddressMatcherCIDRs) == 0 {
		return true
	}
	for _, prefix := range cfg.AddressMatcherCIDRs {
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
}

var DefaultConfig = Config{
	AddressMatcherCIDRs: nil,
	ToIPRange:           netip.MustParsePrefix("169.254.0.0/16"),
}
