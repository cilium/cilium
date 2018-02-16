// Copyright 2017 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package cmd

import (
	"os"
	"text/tabwriter"

	"github.com/cilium/cilium/api/v1/health/models"
	"github.com/cilium/cilium/pkg/command"
	clientPkg "github.com/cilium/cilium/pkg/health/client"

	"github.com/spf13/cobra"
)

var (
	probe   bool
	verbose bool
)

// statusGetCmd represents the status command
var statusGetCmd = &cobra.Command{
	Use:     "status",
	Aliases: []string{"connectivity"},
	Short:   "Display cilium connectivity to other nodes",
	Run: func(cmd *cobra.Command, args []string) {
		var sr *models.HealthStatusResponse

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

		if command.OutputJSON() {
			if err := command.PrintOutput(sr); err != nil {
				os.Exit(1)
			}
		} else {
			w := tabwriter.NewWriter(os.Stdout, 2, 0, 3, ' ', 0)
			clientPkg.FormatHealthStatusResponse(w, sr, verbose)
			w.Flush()
		}
	},
}

func init() {
	rootCmd.AddCommand(statusGetCmd)
	statusGetCmd.Flags().BoolVarP(&probe, "probe", "", false,
		"Synchronously probe connectivity status")
	statusGetCmd.Flags().BoolVarP(&verbose, "verbose", "", false,
		"Print the result verbosely")
	command.AddJSONOutput(statusGetCmd)
}
