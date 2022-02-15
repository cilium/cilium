// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"github.com/spf13/cobra"
)

// recorderCmd represents the recorder command
var recorderCmd = &cobra.Command{
	Use:   "recorder",
	Short: "Introspect or mangle pcap recorder",
}

func init() {
	rootCmd.AddCommand(recorderCmd)
}
