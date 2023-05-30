// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package hive

import (
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/cilium/cilium/pkg/logging"
)

// Command constructs the cobra command for hive. The hive
// command can be used to inspect the dependency graph.
func (h *Hive) Command() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "hive",
		Short: "Inspect the hive",
		Run: func(cmd *cobra.Command, args []string) {
			// Silence log messages from calling invokes and constructors.
			logging.SetLogLevel(logrus.WarnLevel)
			h.PrintObjects()
		},
		TraverseChildren: false,
	}
	h.RegisterFlags(cmd.PersistentFlags())

	cmd.AddCommand(
		&cobra.Command{
			Use:   "dot-graph",
			Short: "Output the dependencies graph in graphviz dot format",
			Run: func(cmd *cobra.Command, args []string) {
				h.PrintDotGraph()
			},
			TraverseChildren: false,
		})

	return cmd
}
