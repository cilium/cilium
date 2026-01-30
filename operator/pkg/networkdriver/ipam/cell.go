// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ipam

import (
	"github.com/cilium/hive/cell"
	"github.com/spf13/pflag"
)

// AutoCreateCiliumResourceIPPools contains pre-defined IP pools to be auto-created on startup.
const AutoCreateCiliumResourceIPPools = "auto-create-cilium-resource-ip-pools"

// Cell implements the operator side of Multi Pool Resource IPAM.
var Cell = cell.Module(
	"multi-pool-resource-ipam",
	"Multi Pool DRA Resource IPAM",

	cell.Config(defaultConfig),

	cell.ProvidePrivate(
		ciliumResourceIPPool,
	),
	cell.Invoke(registerAllocator),
)

type Config struct {
	AutoCreateCiliumResourceIPPools map[string]string
}

var defaultConfig = Config{
	AutoCreateCiliumResourceIPPools: nil,
}

func (cfg Config) Flags(flags *pflag.FlagSet) {
	flags.StringToString(AutoCreateCiliumResourceIPPools, cfg.AutoCreateCiliumResourceIPPools,
		"Automatically create CiliumResourceIPPool resources on startup. "+
			"Specify pools in the form of <pool>=ipv4-cidrs:<cidr>,[<cidr>...];ipv4-mask-size:<size> (multiple pools can also be passed by repeating the CLI flag)")
}
