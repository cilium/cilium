// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package subnet

import "github.com/spf13/pflag"

const (
	SubnetTopologyConfigKey = "subnet-topology"
)

var DefaultConfig = Config{
	Subnets: "",
}

type Config struct {
	Subnets string `json:"subnet-topology,omitempty"`
}

func (cfg Config) Flags(flags *pflag.FlagSet) {
	flags.String(
		SubnetTopologyConfigKey,
		cfg.Subnets,
		"Comma and/or semicolon separated list of subnets in CIDR notation representing the subnet topology.",
	)
	flags.MarkHidden(SubnetTopologyConfigKey)
}
