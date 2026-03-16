// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package externalgroups

import (
	"github.com/cilium/hive/cell"
	"github.com/spf13/pflag"
)

var Cell = cell.Module(
	"network-policy-external-groups",
	"Translates external Groups references in polices to CiliumCIDRGroups",

	cell.Config(defaultExtGroupConfig),
	cell.Provide(NewExternalGroupTable),
	cell.Provide(NewGroupManager),
)

type ExtGroupConfig struct {
	RegisterDummy bool `mapstructure:"register-dummy-external-group"`
}

func (def ExtGroupConfig) Flags(flags *pflag.FlagSet) {
	flags.Bool("register-dummy-external-group", def.RegisterDummy,
		"Register a TEST ONLY policy external group provider")
	flags.MarkHidden("register-dummy-external-group")
}

var defaultExtGroupConfig = ExtGroupConfig{
	RegisterDummy: false,
}
