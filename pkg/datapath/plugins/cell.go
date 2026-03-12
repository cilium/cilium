// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package plugins

import (
	"github.com/cilium/hive/cell"
	"github.com/spf13/pflag"
)

type datapathPluginsConfig struct {
	DatapathPluginsStateDir string
}

func (c datapathPluginsConfig) Flags(flags *pflag.FlagSet) {
	flags.String("datapath-plugins-state-dir", c.DatapathPluginsStateDir, "Parent directory for per-plugin subdirectories containing UNIX sockets for talking to a Cilium datapath plugin.")
}

var defaultDatapathPluginsConfig = datapathPluginsConfig{
	DatapathPluginsStateDir: "/var/run/cilium/plugins",
}

var Cell = cell.Module(
	"datapath-plugins",
	"Controller for Cilium Datapath Plugins",

	cell.Config(defaultDatapathPluginsConfig),
)
