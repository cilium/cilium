// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"os"
	"sort"
	"text/tabwriter"

	"github.com/spf13/cobra"

	pkg "github.com/cilium/cilium/pkg/client"
	"github.com/cilium/cilium/pkg/command"
)

var noHeaders bool

// endpointListCmd represents the endpoint_list command
var endpointListCmd = &cobra.Command{
	Use:     "list",
	Aliases: []string{"ls"},
	Short:   "List all endpoints",
	Run: func(cmd *cobra.Command, args []string) {
		listEndpoints()
	},
}

func init() {
	EndpointCmd.AddCommand(endpointListCmd)
	endpointListCmd.Flags().BoolVar(&noHeaders, "no-headers", false, "Do not print headers")
	command.AddOutputOption(endpointListCmd)
}

func listEndpoints() {
	eps, err := client.EndpointList()
	if err != nil {
		Fatalf("cannot get endpoint list: %s\n", err)
	}

	sort.Slice(eps, func(i, j int) bool { return eps[i].ID < eps[j].ID })

	if command.OutputOption() {
		if err := command.PrintOutput(eps); err != nil {
			os.Exit(1)
		}
		return
	}

	w := tabwriter.NewWriter(os.Stdout, 5, 0, 3, ' ', 0)
	pkg.FormatEndpoints(w, eps, noHeaders)
}
