// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"github.com/spf13/cobra"

	"github.com/cilium/cilium/pkg/maps/ctmap"
)

// BPFCtCmd represents the bpf_ct command
var BPFCtCmd = &cobra.Command{
	Use:   "ct",
	Short: "Connection tracking tables",
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		ctmap.InitMapInfo(true, true, true)
	},
}

func init() {
	BPFCmd.AddCommand(BPFCtCmd)
}
