// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"github.com/spf13/cobra"
)

// RecorderCmd represents the recorder command
var RecorderCmd = &cobra.Command{
	Use:   "recorder",
	Short: "Introspect or mangle pcap recorder",
}

func init() {
	RootCmd.AddCommand(RecorderCmd)
}
