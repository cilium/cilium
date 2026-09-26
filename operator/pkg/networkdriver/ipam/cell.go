// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ipam

import (
	"github.com/cilium/hive/cell"
	"github.com/spf13/pflag"
)

const (
	autoCreateCiliumResourceIPPoolsFlag = "auto-create-cilium-resource-ip-pools"
)

// Cell implements the operator side of Multi-Pool Resource IPAM.
var Cell = cell.Module(
	"multi-pool-resource-ipam",
	"Multi-Pool Resource IPAM",

	cell.Config(defaultConfig),
	cell.ProvidePrivate(ciliumResourceIPPool),
	cell.Invoke(registerAllocator),
)

type Config struct {
	AutoCreatePools map[string]string `mapstructure:"auto-create-cilium-resource-ip-pools"`
}

var defaultConfig = Config{}

func (cfg Config) Flags(flags *pflag.FlagSet) {
	flags.StringToString(autoCreateCiliumResourceIPPoolsFlag, cfg.AutoCreatePools,
		"Automatically create CiliumResourceIPPool resources on startup. "+
			"Specify pools in the form of <pool>=ipv4-cidrs:<cidr>,[<cidr>...];ipv4-mask-size:<size>[;allow-first-ip:<bool>][;allow-last-ip:<bool>] (multiple pools can also be passed by repeating the CLI flag)")
}
