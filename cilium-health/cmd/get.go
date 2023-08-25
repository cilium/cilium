// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/spf13/cobra"

	ciliumClient "github.com/cilium/cilium/pkg/client"
	"github.com/cilium/cilium/pkg/command"
)

// healthGetCmd represents the get command
var healthGetCmd = &cobra.Command{
	Use:     "get",
	Aliases: []string{"inspect", "show"},
	Short:   "Display local cilium agent status",
	Run: func(cmd *cobra.Command, args []string) {
		result, err := client.Restapi.GetHealthz(nil)
		if err != nil {
			Fatalf("Cannot get health for local instance: %s\n", err)
		}
		sr := result.Payload

		if command.OutputOption() {
			if err := command.PrintOutput(sr); err != nil {
				os.Exit(1)
			}
		} else {
			w := tabwriter.NewWriter(os.Stdout, 2, 0, 3, ' ', 0)
			fmt.Fprintf(w, "Daemon uptime:\t%s\n", sr.Uptime)
			load := sr.SystemLoad
			fmt.Fprintf(w, "Node load:\t%s %s %s\n",
				load.Last1min, load.Last5min, load.Last15min)
			ciliumClient.FormatStatusResponse(w, &sr.Cilium, ciliumClient.StatusNoDetails)
			w.Flush()
		}
	},
}

func init() {
	rootCmd.AddCommand(healthGetCmd)
	command.AddOutputOption(healthGetCmd)
}
