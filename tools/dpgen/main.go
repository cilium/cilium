// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
)

func main() {
	var rootCmd = &cobra.Command{
		Use:   "dpgen",
		Short: "dpgen generates Go code from eBPF datapath objects",
	}

	rootCmd.AddCommand(configCmd())
	rootCmd.AddCommand(mapsCmd())
	rootCmd.AddCommand(typesCmd())

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func configCmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "config [file]",
		Short: "Generates a configuration struct from a single datapath object",
		Long: `Generates a configuration struct from a single datapath object.

The struct is generated based on global variables in the object file with a
decl tag matching the provided kind (e.g. "kind:object"). Optionally, additional
structs can be embedded in the generated struct with the --embed flag.

Use with go:generate in a Go source file (e.g. gen.go) to automatically detect
the current package name:

    //go:generate go tool dpgen config --embed Node --kind object --name BPFLXC --out lxc_config.go ../../../bpf/bpf_lxc.o`,
		PreRunE: func(cmd *cobra.Command, args []string) error {
			if configOpts.embed != "" {
				configOpts.embeds = strings.Split(configOpts.embed, ",")
			}
			if configOpts.outName == "" {
				return fmt.Errorf("name cannot be empty")
			}
			if configOpts.outFile == "" {
				return fmt.Errorf("out cannot be empty")
			}
			if configOpts.kind == "" {
				return fmt.Errorf("kind cannot be empty")
			}
			return nil
		},
		RunE: runConfig,
		Args: cobra.ExactArgs(1),
	}

	flags := c.Flags()
	flags.StringVar(&configOpts.outFile, "out", "", "output Go source file for the generated config struct")
	flags.StringVar(&configOpts.outName, "name", "", "name of the generated Go struct in the output file")
	flags.StringVar(&configOpts.kind, "kind", "object", "variables to include based on their decl tags (kind:object, kind:node, ...)")
	flags.StringVar(&configOpts.embed, "embed", "", "comma-separated list of Go structs to embed in the generated struct")
	flags.StringVar(&configOpts.typesPkg, "types", "github.com/cilium/cilium/pkg/datapath/types", "package containing external types managed by 'dpgen type'")

	flags.StringVarP(&configOpts.goPkg, "package", "p", os.Getenv("GOPACKAGE"), "name of the Go package dpgen was invoked for/from (default $GOPACKAGE)")

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
			if mapsOpts.goPkg == "" {
				return fmt.Errorf("package name cannot be empty, set with -p/--package or GOPACKAGE")
			}
			return nil
		},
		RunE: runMaps,
		Args: cobra.MinimumNArgs(1),
	}

	flags := c.Flags()
	flags.StringVarP(&mapsOpts.goPkg, "package", "p", os.Getenv("GOPACKAGE"), "name of the Go package dpgen was invoked for/from (default $GOPACKAGE)")

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

    //go:generate go tool dpgen types ../../../bpf/bpf_*.o`,
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
