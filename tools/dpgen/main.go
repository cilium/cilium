// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
)

var (
	goPkg string
)

func main() {
	var rootCmd = &cobra.Command{
		Use:   "dpgen",
		Short: "dpgen generates Go code from eBPF datapath objects",
	}

	rootCmd.AddCommand(configCmd())
	rootCmd.AddCommand(mapsCmd())

	flags := rootCmd.PersistentFlags()
	flags.StringVarP(&goPkg, "package", "p", os.Getenv("GOPACKAGE"), "name of the Go package dpgen was invoked for/from")

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

var (
	inPath, kind, name, embed, goOut, protoOut, protoImport string
	embeds                                                  []string
	protoImports                                            []string
)

func configCmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "config",
		Short: "Generates a configuration struct from an eBPF datapath object",
		RunE:  runConfig,
		PreRunE: func(cmd *cobra.Command, args []string) error {
			if goPkg == "" {
				return fmt.Errorf("package name cannot be empty, set with -p/--package or GOPACKAGE")
			}

			if embed != "" {
				embeds = strings.Split(embed, ",")
			}

			if protoImport != "" {
				protoImports = strings.Split(protoImport, ",")
			}

			if inPath == "" {
				return fmt.Errorf("path cannot be empty")
			}

			if name == "" {
				return fmt.Errorf("name cannot be empty")
			}

			if goOut == "" {
				return fmt.Errorf("goOut cannot be empty")
			}

			if protoOut == "" {
				return fmt.Errorf("protoOut cannot be empty")
			}

			if kind == "" {
				return fmt.Errorf("kind cannot be empty")
			}
			return nil
		},
	}

	flags := c.Flags()
	flags.StringVar(&inPath, "path", "", "path to the eBPF collection")
	flags.StringVar(&goOut, "go-out", "", "output Go file for the generated config struct")
	flags.StringVar(&protoOut, "proto-out", "", "output Proto file for the generated config message")
	flags.StringVar(&kind, "kind", "object", "kind of the eBPF collection (object or node)")
	flags.StringVar(&name, "name", "", "name of the generated Go struct")
	flags.StringVar(&embed, "embed", "", "comma-separated list of structs to embed")
	flags.StringVar(&protoImport, "proto-import", "", "comma-separated list of extra import paths for proto files")

	return c
}

func mapsCmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "maps [pattern(s) ...]",
		Short: "Generates Go MapSpecs from one or more datapath objects",
		Long: `Generates Go MapSpecs from one or more datapath objects.

Patterns are interpreted as glob patterns to match eBPF object files.

Use with go:generate in a Go source file (e.g. gen.go) to automatically detect
the current package name:

    //go:generate go run github.com/cilium/cilium/tools/dpgen maps ../../../bpf/bpf_*.o

If running outside of go:generate, the package name must be provided with -p/--package.`,
		PreRunE: func(cmd *cobra.Command, args []string) error {
			if goPkg == "" {
				return fmt.Errorf("package name cannot be empty, set with -p/--package or GOPACKAGE")
			}
			return nil
		},
		RunE: runMaps,
		Args: cobra.MinimumNArgs(1),
	}

	return c
}
