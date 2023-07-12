// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"github.com/spf13/cobra"

	"github.com/cilium/cilium/pkg/maps/ctmap"
	"github.com/cilium/cilium/pkg/option"
)

// BPFCtCmd represents the bpf_ct command
var BPFCtCmd = &cobra.Command{
	Use:   "ct",
	Short: "Connection tracking tables",
}

func init() {
	ctmap.InitMapInfo(option.CTMapEntriesGlobalTCPDefault, option.CTMapEntriesGlobalAnyDefault, true, true, true)
	BPFCmd.AddCommand(BPFCtCmd)
}
