// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package config

import (
	"fmt"

	"github.com/cilium/hive/cell"
	"github.com/spf13/pflag"

	"github.com/cilium/cilium/pkg/option"
)

var (
	Cell = cell.Group(
		cell.Config(defaultConfig),
		cell.Provide(config.Out),
	)

	defaultConfig = config{
		WriteCNIConfWhenReady: "",
		ReadCNIConf:           "",
		CNIChainingMode:       "none",
		CNILogFile:            "/var/run/cilium/cilium-cni.log",
		CNIExclusive:          false,
		CNIChainingTarget:     "",
		CNIExternalRouting:    false,
	}
)

type Config struct {
	WriteCNIConfWhenReady string
	ReadCNIConf           string
	CNIChainingMode       string
	CNILogFile            string
	CNIExclusive          bool
	CNIChainingTarget     string
	CNIExternalRouting    bool
}

type config Config

func (def config) Flags(flags *pflag.FlagSet) {
	flags.String(option.WriteCNIConfigurationWhenReady, def.WriteCNIConfWhenReady, "Write the CNI configuration to the specified path when agent is ready")
	flags.String(option.ReadCNIConfiguration, def.ReadCNIConf, fmt.Sprintf("CNI configuration file to use as a source for --%s. If not supplied, a suitable one will be generated.", option.WriteCNIConfigurationWhenReady))
	flags.String(option.CNIChainingMode, def.CNIChainingMode, "Enable CNI chaining with the specified plugin")
	flags.String(option.CNILogFile, def.CNILogFile, "Path where the CNI plugin should write logs")
	flags.String(option.CNIChainingTarget, def.CNIChainingTarget, "CNI network name into which to insert the Cilium chained configuration. Use '*' to select any network.")
	flags.Bool(option.CNIExclusive, def.CNIExclusive, "Whether to remove other CNI configurations")
	flags.Bool(option.CNIExternalRouting, def.CNIExternalRouting, "Whether the chained CNI plugin handles routing on the node")
}

func (cfg config) Out() Config {
	if cfg.CNIChainingMode == "aws-cni" && cfg.CNIChainingTarget == "" {
		cfg.CNIChainingTarget = "aws-cni"
		cfg.CNIExternalRouting = true
	}

	if cfg.CNIChainingTarget != "" && cfg.CNIChainingMode == "" {
		cfg.CNIChainingMode = "generic-veth"
	}

	if cfg.CNIChainingMode == "" {
		cfg.CNIChainingMode = "none"
	}

	return Config(cfg)
}
