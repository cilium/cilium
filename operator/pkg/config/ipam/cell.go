// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ipam

import (
	"github.com/cilium/hive/cell"
	"github.com/spf13/pflag"

	operatorOption "github.com/cilium/cilium/operator/option"
	"github.com/cilium/cilium/pkg/defaults"
)

// Config contains the IPAM allocation parameters configuration.
type Config struct {
	IPAMPreAllocate       int `mapstructure:"ipam-pre-allocate"`
	IPAMMinAllocate       int `mapstructure:"ipam-min-allocate"`
	IPAMMaxAllocate       int `mapstructure:"ipam-max-allocate"`
	IPAMMaxAboveWatermark int `mapstructure:"ipam-max-above-watermark"`
}

// Flags implements the cell.Flagger interface, registering the IPAM allocation flags.
func (cfg Config) Flags(flags *pflag.FlagSet) {
	flags.Int(operatorOption.IPAMPreAllocate, cfg.IPAMPreAllocate,
		"Number of IP addresses that must be pre-allocated when using cloud provider IPAM modes. "+
			"If this value exceeds the instance type limits, it will be automatically clamped to the maximum safe value for the instance type")

	flags.Int(operatorOption.IPAMMinAllocate, cfg.IPAMMinAllocate,
		"Minimum number of IP addresses that must be allocated when using cloud provider IPAM modes")

	flags.Int(operatorOption.IPAMMaxAllocate, cfg.IPAMMaxAllocate,
		"Maximum number of IP addresses that can be allocated to a node when using cloud provider IPAM modes (0 = unlimited)")

	flags.Int(operatorOption.IPAMMaxAboveWatermark, cfg.IPAMMaxAboveWatermark,
		"Maximum number of IP addresses that can be allocated beyond the current need when using cloud provider IPAM modes")
}

var defaultConfig = Config{
	IPAMPreAllocate:       defaults.IPAMPreAllocation,
	IPAMMinAllocate:       defaults.IPAMMinAllocation,
	IPAMMaxAllocate:       defaults.IPAMMaxAllocation,
	IPAMMaxAboveWatermark: defaults.IPAMMaxAboveWatermark,
}

// Cell provides the IPAM allocation parameters configuration cell.
var Cell = cell.Module(
	"operator-ipam-config",
	"Operator IPAM Configuration",

	cell.Config(defaultConfig),
)
