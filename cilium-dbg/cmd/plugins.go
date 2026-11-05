// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"github.com/spf13/cobra"
)

// PluginsCmd represents the plugins command
var PluginsCmd = &cobra.Command{
	Use:   "plugins",
	Short: "Query plugins status",
}

func init() {
	RootCmd.AddCommand(PluginsCmd)
}
