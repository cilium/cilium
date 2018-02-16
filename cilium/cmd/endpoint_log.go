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

	"github.com/cilium/cilium/pkg/command"

	"github.com/spf13/cobra"
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
	command.AddJSONOutput(endpointLogCmd)
}

func getEndpointLog(cmd *cobra.Command, args []string) {
	requireEndpointID(cmd, args)
	eID := args[0]
	epLog, err := client.EndpointLogGet(eID)
	if err != nil {
		Fatalf("Cannot get endpoint log %s: %s\n", eID, err)
	}

	if command.OutputJSON() {
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
