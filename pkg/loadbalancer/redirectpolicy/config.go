// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package redirectpolicy

import (
	"net/netip"

	"github.com/cilium/hive/cell"
	"github.com/spf13/pflag"
)

const (
	AddressMatcherCIDRsName       = "lrp-address-matcher-cidrs"
	EnableLocalRedirectPolicyName = "enable-local-redirect-policy"
)

// Config provides Local Redirect Policy configuration.
type Config interface {
	IsEnabled() bool
	AddressAllowed(netip.Addr) bool
}

type lrpUserConfig struct {
	EnableConfig `mapstructure:",squash"`

	// AddressMatcherCIDRs limits which addresses can be used in an
	// AddressMatcher rule to specific CIDRs. This allows global control over
	// what addresses can be matched over the namespaced CiliumLocalRedirectPolicies.
	AddressMatcherCIDRs []netip.Prefix `mapstructure:"lrp-address-matcher-cidrs"`
}

var (
	defaultEnableConfig  = EnableConfig{}
	defaultLRPUserConfig = lrpUserConfig{EnableConfig: defaultEnableConfig}
)

// EnableConfig is the Local Redirect Policy configuration shared by the agent
// and operator.
type EnableConfig struct {
	// EnableLocalRedirectPolicy enables redirect policies to redirect traffic within nodes.
	EnableLocalRedirectPolicy bool `mapstructure:"enable-local-redirect-policy"`
}

func (def EnableConfig) Flags(flags *pflag.FlagSet) {
	flags.Bool(EnableLocalRedirectPolicyName, def.EnableLocalRedirectPolicy, "Enable Local Redirect Policy")
}

func (cfg EnableConfig) IsEnabled() bool {
	return cfg.EnableLocalRedirectPolicy
}

func (def lrpUserConfig) Flags(flags *pflag.FlagSet) {
	def.EnableConfig.Flags(flags)
	flags.StringSlice(AddressMatcherCIDRsName, []string{}, "Limit address matches to specific CIDRs")
}

type lrpAgentConfig struct {
	enableLocalRedirectPolicy bool
	addressMatcherCIDRs       []netip.Prefix
}

func newLRPAgentConfig(cfg lrpUserConfig) Config {
	return lrpAgentConfig{
		enableLocalRedirectPolicy: cfg.EnableLocalRedirectPolicy,
		addressMatcherCIDRs:       cfg.AddressMatcherCIDRs,
	}
}

func (cfg lrpAgentConfig) IsEnabled() bool {
	return cfg.enableLocalRedirectPolicy
}

func (cfg lrpAgentConfig) AddressAllowed(addr netip.Addr) bool {
	if len(cfg.addressMatcherCIDRs) == 0 {
		return true
	}
	for _, prefix := range cfg.addressMatcherCIDRs {
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
}

// ConfigCell provides Local Redirect Policy configuration.
var ConfigCell = cell.Group(
	cell.Config(defaultLRPUserConfig),
	cell.Provide(newLRPAgentConfig),
)
