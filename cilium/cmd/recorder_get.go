// Copyright 2021 Authors of Cilium
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
	"strconv"
	"text/tabwriter"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/command"

	"github.com/spf13/cobra"
)

// recorderGetCmd represents the recorder_get command
var recorderGetCmd = &cobra.Command{
	Use:    "get <recorder id>",
	Short:  "Display individual pcap recorder",
	PreRun: requireRecorderID,
	Run: func(cmd *cobra.Command, args []string) {
		recIDstr := args[0]
		id, err := strconv.ParseInt(recIDstr, 0, 64)
		if err != nil {
			Fatalf("Unable to parse recorder ID: %s", recIDstr)
		}

		rec, err := client.GetRecorderID(id)
		if err != nil {
			Fatalf("Cannot get recorder '%v': %s\n", id, err)
		}
		if command.OutputJSON() {
			if err := command.PrintOutput(rec); err != nil {
				os.Exit(1)
			}
			return
		}
		if rec.Status == nil || rec.Status.Realized == nil {
			Fatalf("Cannot get recorder '%v': empty response\n", id)
		}
		w := tabwriter.NewWriter(os.Stdout, 5, 0, 3, ' ', 0)
		list := []*models.Recorder{}
		list = append(list, rec)
		printRecorderList(w, list)
	},
}

func init() {
	recorderCmd.AddCommand(recorderGetCmd)
	command.AddJSONOutput(recorderGetCmd)
}
