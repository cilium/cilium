// Copyright 2019 Authors of Cilium
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

	daemonAPI "github.com/cilium/cilium/api/v1/client/daemon"
	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/api"
	"github.com/cilium/cilium/pkg/command"

	"github.com/spf13/cobra"
)

var mapGetHistory = &cobra.Command{
	Use:     "history <name>",
	Short:   "Display BPF map operations history",
	Example: "cilium map get cilium_ipcache history",
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) == 0 {
			Fatalf("map name must be specified")
		}

		params := daemonAPI.NewGetMapNameHistoryParams().WithName(
			args[0]).WithTimeout(api.ClientTimeout)

		resp, noContentResp, err := client.Daemon.GetMapNameHistory(params)
		if err != nil {
			Fatalf(err.Error())
		}
		if noContentResp != nil {
			fmt.Fprintf(os.Stderr,
				"BPF map operations history is disabled. To enable it, use --debug option in cilium-agent.\n")
			return
		}

		history := resp.Payload
		if history == nil {
			return
		}

		if command.OutputJSON() {
			if err := command.PrintOutput(history); err != nil {
				os.Exit(1)
			}
		} else {
			printMapHistory(history)
		}
	},
}

func printMapHistory(history *models.BPFMapHistory) {
	w := tabwriter.NewWriter(os.Stdout, 5, 0, 3, ' ', 0)
	fmt.Fprintf(w, "Timestamp\tAction\tKey\tValue\tError\n")
	for _, entry := range history.Entries {
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n",
			entry.Timestamp,
			entry.Action,
			entry.Key,
			entry.Value,
			entry.Error)
	}
	w.Flush()
}

func init() {
	mapCmd.AddCommand(mapGetHistory)
	command.AddJSONOutput(mapGetHistory)
}
