// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cell

import (
	"github.com/spf13/pflag"

	"github.com/cilium/cilium/pkg/option"
)

type Config struct {
	EnableIPMasqAgent     bool   `mapstructure:"enable-ip-masq-agent"`
	IPMasqAgentConfigPath string `mapstructure:"ip-masq-agent-config-path"`
}

var defaultConfig = Config{
	EnableIPMasqAgent:     false,
	IPMasqAgentConfigPath: "/etc/config/ip-masq-agent",
}

func (c Config) Flags(flags *pflag.FlagSet) {
	flags.Bool(option.EnableIPMasqAgent, c.EnableIPMasqAgent, "Enable BPF ip-masq-agent")
	flags.String(option.IPMasqAgentConfigPath, c.IPMasqAgentConfigPath, "ip-masq-agent configuration file path")
}
