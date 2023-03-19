// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"errors"
	"fmt"
	"os"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/cilium/cilium/bugtool/configuration"
	"github.com/cilium/cilium/bugtool/options"
)

var config = &options.Config{}

func init() {
	config.Flags(BugtoolRootCmd.Flags())
}

// BugtoolRootCmd is the top level command for the bugtool.
var BugtoolRootCmd = &cobra.Command{
	Use:   "cilium-bugtool [OPTIONS]",
	Short: "Collects agent & system information useful for bug reporting",
	Example: `	# Collect information and create archive file
	$ cilium-bugtool
	[...]
`,
	Run: func(cmd *cobra.Command, _ []string) {
		// Create config and parse flags
		config := &options.Config{}
		flags := pflag.NewFlagSet("bugtool", pflag.ExitOnError)
		config.Flags(flags)
		if err := flags.Parse(os.Args[1:]); err != nil {
			if errors.Is(err, pflag.ErrHelp) {
				os.Exit(0)
			}
			log.Fatalf("Failed to parse flags: %s", err)
		}

		// Create v2 Bugtool.
		bugtoolV2 := CreateBugtool(config)

		// Create dump config tree.
		root := configuration.CreateDump(config)

		// Run tool.
		bugtoolV2.runTool(
			cmd.Context(),
			config,
			root,
		)
	},
}

const (
	disclaimer = `
╭───────────────────────────────────────────────────────────╮
│ DISCLAIMER:                                               │
│                                                           │
│ This tool has copied information about your environment.  │
│ If you are going to register a issue on GitHub, please    │
│ only provide files from the archive you have reviewed     │
│ for sensitive information.                                │
╰───────────────────────────────────────────────────────────╯
`
)

func cleanup(dbgDir string, config *options.Config) {
	if config.Archive {
		var files []string

		switch config.ArchiveType {
		case "gz":
			files = append(files, dbgDir)
			files = append(files, fmt.Sprintf("%s.tar", dbgDir))
		case "tar":
			files = append(files, dbgDir)
		}

		for _, file := range files {
			if err := os.RemoveAll(file); err != nil {
				fmt.Fprintf(os.Stderr, "Failed to cleanup temporary files %s\n", err)
			}
		}
	}
}
