// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
)

var inPath, kind, name, embed, out, pkg string
var embeds []string

func main() {
	var rootCmd = &cobra.Command{
		Use:   "dpgen",
		Short: "dpgen generates go code from eBPF datapath objects",
	}

	rootCmd.AddCommand(configCmd())
	rootCmd.AddCommand(mapsCmd())

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func configCmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "config",
		Short: "Generates a configuration struct from an eBPF datapath object",
		RunE:  runConfig,
		PreRunE: func(cmd *cobra.Command, args []string) error {
			if embed != "" {
				embeds = strings.Split(embed, ",")
			}

			if inPath == "" {
				return fmt.Errorf("path cannot be empty")
			}

			if name == "" {
				return fmt.Errorf("name cannot be empty")
			}

			if out == "" {
				return fmt.Errorf("out cannot be empty")
			}

			if kind != "object" && kind != "node" {
				return fmt.Errorf("kind needs to be 'object' or 'node'")
			}
			return nil
		},
	}

	flags := c.Flags()
	flags.StringVar(&inPath, "path", "", "path to the eBPF collection")
	flags.StringVar(&out, "out", "", "output Go file for the generated config struct")
	flags.StringVar(&kind, "kind", "object", "kind of the eBPF collection (object or node)")
	flags.StringVar(&name, "name", "", "name of the generated Go struct")
	flags.StringVar(&embed, "embed", "", "comma-separated list of structs to embed")

	return c
}

func mapsCmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "maps {path to object files...}",
		Short: "Generates Go code for eBPF maps from a datapath objects",
		PreRunE: func(cmd *cobra.Command, args []string) error {
			if out == "" {
				return fmt.Errorf("out cannot be empty")
			}
			return nil
		},
		RunE: runMaps,
		Args: cobra.MinimumNArgs(1),
	}

	flags := c.Flags()
	flags.StringVar(&out, "out", "", "output directory for the generated Go file and BTF blob")
	flags.StringVar(&pkg, "package", "maps", "name of the Go package")

	return c
}
