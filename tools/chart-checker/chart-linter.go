// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package main

import (
	"fmt"
	"log"
	"os"

	"github.com/spf13/cobra"

	"github.com/cilium/cilium/tools/chart-checker/linters"
)

// Chart-linter enforces some cilium-specific requirements when rendering charts

func main() {
	var chartPath string
	var values []string

	cmd := &cobra.Command{
		Short: "helm linter",
		RunE: func(_ *cobra.Command, _ []string) error {

			if chartPath == "" {
				return fmt.Errorf("chart-path is required")
			}

			err := lint(chartPath, values)
			if err == nil {
				log.Println("lint OK!")
			}
			return err
		},

		SilenceUsage: true,
	}

	flags := cmd.PersistentFlags()
	flags.StringVar(&chartPath, "chart-path", "", "Path to helm chart")
	cmd.Flags().StringArrayVar(&values, "set", []string{}, "Set helm values on the command line (can specify multiple or separate values with commas: key1=val1,key2=val2)")

	if err := cmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func lint(chartPath string, values []string) error {
	failed := false
	for _, linter := range linters.Linters {
		if err := linter.Lint(chartPath, values); err != nil {
			log.Printf("%s failed: %v\t(%s)",
				linter.Name(), err.Error(), linter.Description())
			failed = true
		} else {
			log.Printf("OK %s", linter.Name())
		}
	}

	if failed {
		return fmt.Errorf("some linters failed")
	}
	return nil
}
