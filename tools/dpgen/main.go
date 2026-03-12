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
	rootCmd.AddCommand(typesCmd())

	flags := rootCmd.Flags()
	flags.StringVarP(&goPkg, "package", "p", os.Getenv("GOPACKAGE"), "name of the Go package dpgen was invoked for/from")

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

var (
	inPath, kind, name, embed, out string
	embeds                         []string
)

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

			if kind == "" {
				return fmt.Errorf("kind cannot be empty")
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
		Use:   "maps [pattern(s) ...]",
		Short: "Generates Go MapSpecs from one or more datapath objects",
		Long: `Generates Go MapSpecs from one or more datapath objects.

Patterns are interpreted as glob patterns to match eBPF object files.

Use with go:generate in a Go source file (e.g. gen.go) to automatically detect
the current package name:

    //go:generate go tool dpgen maps ../../../bpf/bpf_*.o

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

func typesCmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "types [pattern(s) ...]",
		Short: "Generate Go type declarations from one or more datapath objects",
		Long: `Generate Go type declarations from one or more datapath objects.

Collect types appearing directly in pinned maps and global variables from one
or more eBPF object files and merge them into a single set of Go type
declarations. Emit a single Go source file in the current package.

Patterns are interpreted as glob patterns to match eBPF object files. All files
must be provided in a single invocation in order for dpgen to merge their BTF.

Use with go:generate in a Go source file (e.g. gen.go) to automatically detect
the current package name:

    //go:generate go run github.com/cilium/cilium/tools/dpgen types ../../../bpf/bpf_*.o`,
		PreRunE: func(cmd *cobra.Command, args []string) error {
			if typesOpts.goPkg == "" {
				return fmt.Errorf("package name cannot be empty, set with -p/--package or GOPACKAGE")
			}
			return nil
		},
		RunE: runTypes,
		Args: cobra.MinimumNArgs(1),
	}

	flags := c.Flags()
	flags.StringVarP(&typesOpts.goPkg, "package", "p", os.Getenv("GOPACKAGE"), "name of the Go package dpgen was invoked for/from (default $GOPACKAGE)")

	return c
}
