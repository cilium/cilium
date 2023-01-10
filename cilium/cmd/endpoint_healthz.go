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

// endpointHealthCmd represents the endpoint_healthz command
var endpointHealthCmd = &cobra.Command{
	Use:     "health <endpoint id>",
	Short:   "View endpoint health",
	Example: "cilium endpoint health 5421",
	Run: func(cmd *cobra.Command, args []string) {
		requireEndpointID(cmd, args)
		getEndpointHealth(cmd, args)
	},
}

func init() {
	endpointCmd.AddCommand(endpointHealthCmd)
	command.AddOutputOption(endpointHealthCmd)
}

func getEndpointHealth(cmd *cobra.Command, args []string) {
	requireEndpointID(cmd, args)
	eID := args[0]
	epHealth, err := client.EndpointHealthGet(eID)
	if err != nil {
		Fatalf("Cannot get endpoint healthz %s: %s\n", eID, err)
	}

	if command.OutputOption() {
		if err := command.PrintOutput(epHealth); err != nil {
			os.Exit(1)
		}
	} else {
		w := tabwriter.NewWriter(os.Stdout, 2, 0, 3, ' ', 0)
		fmt.Fprintf(w, "Overall Health:\t%s\n", epHealth.OverallHealth)
		fmt.Fprintf(w, "BPF Health:\t%s\n", epHealth.Bpf)
		fmt.Fprintf(w, "Policy Health:\t%s\n", epHealth.Policy)
		connected := map[bool]string{true: "yes", false: "no"}
		fmt.Fprintf(w, "Connected:\t%s\n", connected[epHealth.Connected])
		w.Flush()
	}
}
