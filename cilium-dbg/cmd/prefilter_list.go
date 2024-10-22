// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/cilium/cilium/pkg/command"
)

var preFilterListCmd = &cobra.Command{
	Use:     "list",
	Aliases: []string{"ls"},
	Short:   "List CIDR filters",
	Run: func(cmd *cobra.Command, args []string) {
		listFilters(cmd, args)
	},
}

func init() {
	PreFilterCmd.AddCommand(preFilterListCmd)
	command.AddOutputOption(preFilterListCmd)
}

func listFilters(cmd *cobra.Command, args []string) {
	spec, err := client.GetPrefilter()
	if err != nil {
		Fatalf("Cannot get CIDR list: %s", err)
	}

	if command.OutputOption() {
		if err := command.PrintOutput(spec); err != nil {
			os.Exit(1)
		}
		return
	}

	if spec.Status == nil || spec.Status.Realized == nil {
		Fatalf("Cannot get CIDR list: empty response")
	}
	w := tabwriter.NewWriter(os.Stdout, 5, 0, 3, ' ', 0)
	fmt.Fprintf(w, "Revision: %d\n", spec.Status.Realized.Revision)
	for _, pfx := range spec.Status.Realized.Deny {
		fmt.Fprintln(w, pfx)
	}
	w.Flush()
}
