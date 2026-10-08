// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package redirectpolicy

import (
	"net/netip"

	"github.com/spf13/pflag"
)

const (
	AddressMatcherCIDRsName = "lrp-address-matcher-cidrs"
)

type Config struct {
	// AddressMatcherCIDRs limits which addresses can be used in a
	// AddressMatcher rule to specific CIDRs. This allows global control over
	// what addresses can be matched over the namespaced CiliumLocalRedirectPolicies.
	AddressMatcherCIDRs []netip.Prefix `mapstructure:"lrp-address-matcher-cidrs"`
}

func (def Config) Flags(flags *pflag.FlagSet) {
	flags.StringSlice(AddressMatcherCIDRsName, []string{}, "Limit address matches to specific CIDRs")
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
}
