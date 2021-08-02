// SPDX-License-Identifier: Apache-2.0
// Copyright 2017 Authors of Cilium

package cmd

import (
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/cilium/cilium/pkg/command"

	"github.com/spf13/cobra"
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
	preFilterCmd.AddCommand(preFilterListCmd)
	command.AddJSONOutput(preFilterListCmd)
}

func listFilters(cmd *cobra.Command, args []string) {
	var str string
	spec, err := client.GetPrefilter()
	if err != nil {
		Fatalf("Cannot get CIDR list: %s", err)
	}

	if command.OutputJSON() {
		if err := command.PrintOutput(spec); err != nil {
			os.Exit(1)
		}
		return
	}

	if spec.Status == nil || spec.Status.Realized == nil {
		Fatalf("Cannot get CIDR list: empty response")
	}
	w := tabwriter.NewWriter(os.Stdout, 5, 0, 3, ' ', 0)
	str = fmt.Sprintf("Revision: %d", spec.Status.Realized.Revision)
	fmt.Fprintln(w, str)
	for _, pfx := range spec.Status.Realized.Deny {
		str = fmt.Sprintf("%s", pfx)
		fmt.Fprintln(w, str)
	}
	w.Flush()
}
