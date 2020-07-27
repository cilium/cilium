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
	"fmt"
	"os"
	"text/tabwriter"

	ciliumClient "github.com/cilium/cilium/pkg/client"
	"github.com/cilium/cilium/pkg/command"

	"github.com/spf13/cobra"
)

// healthGetCmd represents the get command
var healthGetCmd = &cobra.Command{
	Use:     "get",
	Aliases: []string{"inspect, show"},
	Short:   "Display local cilium agent status",
	Run: func(cmd *cobra.Command, args []string) {
		result, err := client.Restapi.GetHealthz(nil)
		if err != nil {
			Fatalf("Cannot get health for local instance: %s\n", err)
		}
		sr := result.Payload

		if command.OutputJSON() {
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
	command.AddJSONOutput(healthGetCmd)
}
