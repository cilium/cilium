// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"strconv"

	"github.com/spf13/cobra"
)

// recorderDeleteCmd represents the recorder_delete command
var recorderDeleteCmd = &cobra.Command{
	Use:    "delete <recorder id>",
	Short:  "Delete individual pcap recorder",
	PreRun: requireRecorderID,
	Run: func(cmd *cobra.Command, args []string) {
		recIDstr := args[0]
		id, err := strconv.ParseInt(recIDstr, 0, 64)
		if err != nil {
			Fatalf("Unable to parse recorder ID: %s", recIDstr)
		}

		err = client.DeleteRecorderID(id)
		if err != nil {
			Fatalf("Cannot delete recorder '%v': %s\n", id, err)
		}
	},
}

func init() {
	recorderCmd.AddCommand(recorderDeleteCmd)
}
