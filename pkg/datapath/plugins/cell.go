// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package plugins

import (
	"github.com/cilium/hive/cell"
	"github.com/spf13/pflag"
)

type datapathPluginsConfig struct {
	DatapathPluginsEnabled  bool
	DatapathPluginsStateDir string
}

func (c datapathPluginsConfig) Flags(flags *pflag.FlagSet) {
	flags.Bool("datapath-plugins-enabled", c.DatapathPluginsEnabled, "Flag to enable datapath plugins.")
	flags.String("datapath-plugins-state-dir", c.DatapathPluginsStateDir, "Parent directory for per-plugin subdirectories containing UNIX sockets for talking to a Cilium datapath plugin along with state related to that plugin.")
}

var defaultDatapathPluginsConfig = datapathPluginsConfig{}

var Cell = cell.Module(
	"datapath-plugins",
	"Controller for Cilium Datapath Plugins",

	cell.Config(defaultDatapathPluginsConfig),
)
