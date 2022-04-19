// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"os"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/cilium/cilium/api/v1/health/models"
	"github.com/cilium/cilium/pkg/command"
	clientPkg "github.com/cilium/cilium/pkg/health/client"
)

var (
	probe    bool
	succinct bool
	verbose  bool
)

// statusGetCmd represents the status command
var statusGetCmd = &cobra.Command{
	Use:     "status",
	Aliases: []string{"connectivity"},
	Short:   "Display cilium connectivity to other nodes",
	Run: func(cmd *cobra.Command, args []string) {
		var sr *models.HealthStatusResponse

		if client == nil {
			Fatalf("Invalid combination of arguments")
		}

		if probe {
			result, err := client.Connectivity.PutStatusProbe(nil)
			if err != nil {
				Fatalf("Cannot get status/probe: %s\n", err)
			}
			sr = result.Payload
		} else {
			result, err := client.Connectivity.GetStatus(nil)
			if err != nil {
				Fatalf("Cannot get status: %s\n", err)
			}
			sr = result.Payload
		}

		if command.OutputOption() {
			if err := command.PrintOutput(sr); err != nil {
				os.Exit(1)
			}
		} else {
			w := tabwriter.NewWriter(os.Stdout, 2, 0, 3, ' ', 0)
			clientPkg.FormatHealthStatusResponse(w, sr, true, succinct, verbose, 0)
			w.Flush()
		}
	},
}

func init() {
	rootCmd.AddCommand(statusGetCmd)
	statusGetCmd.Flags().BoolVarP(&probe, "probe", "", false,
		"Synchronously probe connectivity status")
	statusGetCmd.Flags().BoolVarP(&succinct, "succinct", "", false,
		"Print the result succinctly (one node per line)")
	statusGetCmd.Flags().BoolVarP(&verbose, "verbose", "", false,
		"Print more information in results")
	command.AddOutputOption(statusGetCmd)
}
