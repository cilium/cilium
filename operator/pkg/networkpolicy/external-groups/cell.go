// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package externalgroups

import (
	"time"

	"github.com/cilium/hive/cell"
	"github.com/spf13/pflag"
)

var Cell = cell.Module(
	"network-policy-external-groups",
	"Translates external Groups references in polices to CiliumCIDRGroups",

	cell.Config(defaultExtGroupConfig),
	cell.Provide(NewExternalGroupTable),
	cell.Provide(NewGroupManager),
	cell.Invoke(registerPolicyToGroupController),
)

type ExtGroupConfig struct {
	RegisterDummy bool `mapstructure:"register-dummy-external-group"`

	ExternalGroupSyncInterval time.Duration `mapstructure:"policy-external-group-sync-interval"`
}

func (def ExtGroupConfig) Flags(flags *pflag.FlagSet) {
	flags.Bool("register-dummy-external-group", def.RegisterDummy,
		"Register a TEST ONLY policy external group provider")
	flags.MarkHidden("register-dummy-external-group")

	flags.Duration("policy-external-group-sync-interval", def.ExternalGroupSyncInterval,
		"Period between refreshing the CIDRs for a given policy external group.")
}

var defaultExtGroupConfig = ExtGroupConfig{
	RegisterDummy:             false,
	ExternalGroupSyncInterval: 10 * time.Minute,
}
