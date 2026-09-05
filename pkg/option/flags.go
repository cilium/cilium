// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package option

import (
	"github.com/spf13/pflag"
	"github.com/spf13/viper"

	"github.com/cilium/cilium/pkg/defaults"
)

// RegisterCommonPolicyFlags registers options used by policy validation.
func RegisterCommonPolicyFlags(vp *viper.Viper, flags *pflag.FlagSet) {
	flags.Bool(EnableL7Proxy, defaults.EnableL7Proxy, "Enable L7 proxy for L7 policy enforcement")
	BindEnv(vp, EnableL7Proxy)

	flags.Bool(EnableICMPRules, defaults.EnableICMPRules, "Enable ICMP-based rule support for Cilium Network Policies")
	flags.MarkHidden(EnableICMPRules)
	BindEnv(vp, EnableICMPRules)

	flags.Bool(EnableNodeSelectorLabels, defaults.EnableNodeSelectorLabels, "Enable use of node label based identity")
	BindEnv(vp, EnableNodeSelectorLabels)

	flags.Bool(EnableNonDefaultDenyPolicies, defaults.EnableNonDefaultDenyPolicies, "Enable use of non-default-deny policies")
	flags.MarkHidden(EnableNonDefaultDenyPolicies)
	BindEnv(vp, EnableNonDefaultDenyPolicies)

	flags.Bool(EnableExtendedIPProtocols, defaults.EnableExtendedIPProtocols, "Enable traffic with extended IP protocols in datapath")
	BindEnv(vp, EnableExtendedIPProtocols)
}
