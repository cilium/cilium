// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"os"
	"strconv"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/command"
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
		if command.OutputOption() {
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
	command.AddOutputOption(recorderGetCmd)
}
