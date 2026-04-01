// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package networkpolicy

import (
	"github.com/cilium/hive/cell"
	"github.com/spf13/pflag"

	externalgroups "github.com/cilium/cilium/operator/pkg/networkpolicy/external-groups"
	"github.com/cilium/cilium/operator/pkg/networkpolicy/secretsync"
)

var Cell = cell.Module(
	"network-policy",
	"Manages network policy",

	cell.Config(defaultConfig),
	cell.Invoke(registerPolicyValidator),
	cell.Invoke(registerLabelPrefixConfig),

	// Synchronizes policy external groups (toGroups / fromGroups) to CiliumCIDRGroups.
	externalgroups.Cell,

	// Synchronizes Secrets referenced in CiliumNetworkPolicy to the configured secret
	// namespace.
	secretsync.Cell,
)

type Config struct {
	ValidateNetworkPolicy bool `mapstructure:"validate-network-policy"`

	MeshAuthEnabled bool `mapstructure:"mesh-auth-enabled"`
}

var defaultConfig = Config{
	ValidateNetworkPolicy: true,

	MeshAuthEnabled: false,
}

func (def Config) Flags(flags *pflag.FlagSet) {
	flags.Bool("validate-network-policy", def.ValidateNetworkPolicy, "Whether to enable or disable the informational network policy validator")

	flags.Bool("mesh-auth-enabled", def.MeshAuthEnabled, "Enable authentication processing & garbage collection (beta)")
}
