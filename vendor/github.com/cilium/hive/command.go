// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package hive

import (
	"log/slog"
	"os"

	"github.com/spf13/cobra"
)

// Command constructs the cobra command for hive. The hive
// command can be used to inspect the dependency graph.
func (h *Hive) Command() *cobra.Command {
	cmd := &cobra.Command{
		Use:          "hive",
		Short:        "Inspect the hive",
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return h.PrintObjects(os.Stdout, slog.Default())
		},
		TraverseChildren: false,
	}
	h.RegisterFlags(cmd.PersistentFlags())

	cmd.AddCommand(
		&cobra.Command{
			Use:          "dot-graph",
			Short:        "Output the dependencies graph in graphviz dot format",
			SilenceUsage: true,
			RunE: func(cmd *cobra.Command, args []string) error {
				return h.PrintDotGraph()
			},
			TraverseChildren: false,
		})

	return cmd
}
