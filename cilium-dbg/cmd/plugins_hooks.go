// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"fmt"
	"os"
	"strings"

	"github.com/cilium/hive/shell"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/cilium/cilium/pkg/datapath/plugins"
	"github.com/cilium/cilium/pkg/hive"
)

// pluginsHooksCmd represents the plugins hooks command
var pluginsHooksCmd = &cobra.Command{
	Use:   "hooks",
	Short: "Display information about active datapath plugin hooks",
}

func invokeHiveShell(shellCmd string, cmd *cobra.Command) error {
	cfg := hive.DefaultShellConfig
	if err := cfg.Parse(cmd.Flags()); err != nil {
		return err
	}

	var shellArgs []string

	cmd.Flags().Visit(func(f *pflag.Flag) {
		shellArgs = append(shellArgs, fmt.Sprintf("--%s=%s", f.Name, f.Value.String()))
	})

	err := shell.ShellExchange(cfg, os.Stdout, shellCmd+" "+strings.Join(shellArgs, " "))
	if err != nil {
		os.Exit(1)
	}
	return nil
}

// pluginsHooksListCmd represents the plugins hooks list command
var pluginsHooksListCmd = &cobra.Command{
	Use:   "list",
	Short: "List active datapath plugin hooks in attachment order",
	RunE: func(cmd *cobra.Command, args []string) error {
		return invokeHiveShell("plugins/hooks/list", cmd)
	},
}

// pluginsHooksOrderCmd represents the plugins hooks order command
var pluginsHooksOrderCmd = &cobra.Command{
	Use:   "order",
	Short: "Explain active datapath plugin hook ordering",
	RunE: func(cmd *cobra.Command, args []string) error {
		return invokeHiveShell("plugins/hooks/order", cmd)
	},
}

func init() {
	PluginsCmd.AddCommand(pluginsHooksCmd)

	pluginsHooksCmd.AddCommand(pluginsHooksListCmd)
	plugins.BindHookStatusFlags(pluginsHooksListCmd.Flags())
	hive.DefaultShellConfig.Flags(pluginsHooksListCmd.Flags())

	pluginsHooksCmd.AddCommand(pluginsHooksOrderCmd)
	plugins.BindHookStatusFlags(pluginsHooksOrderCmd.Flags())
	hive.DefaultShellConfig.Flags(pluginsHooksOrderCmd.Flags())
}
