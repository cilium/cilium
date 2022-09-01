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

// endpointLogCmd represents the endpoint_log command
var endpointLogCmd = &cobra.Command{
	Use:     "log <endpoint id>",
	Short:   "View endpoint status log",
	Example: "cilium endpoint log 5421",
	Run: func(cmd *cobra.Command, args []string) {
		requireEndpointID(cmd, args)
		getEndpointLog(cmd, args)
	},
}

func init() {
	endpointCmd.AddCommand(endpointLogCmd)
	command.AddOutputOption(endpointLogCmd)
}

func getEndpointLog(cmd *cobra.Command, args []string) {
	requireEndpointID(cmd, args)
	eID := args[0]
	epLog, err := client.EndpointLogGet(eID)
	if err != nil {
		Fatalf("Cannot get endpoint log %s: %s\n", eID, err)
	}

	if command.OutputOption() {
		if err := command.PrintOutput(epLog); err != nil {
			os.Exit(1)
		}
	} else {
		w := tabwriter.NewWriter(os.Stdout, 2, 0, 3, ' ', 0)
		fmt.Fprintf(w, "%s\t%s\t%s\t%v\n", "Timestamp", "Status", "State", "Message")
		for _, entry := range epLog {
			fmt.Fprintf(w, "%s\t%s\t%s\t%v\n", entry.Timestamp, entry.Code, entry.State, entry.Message)
		}
		w.Flush()
	}
}
