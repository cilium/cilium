// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"github.com/spf13/cobra"

	"github.com/cilium/cilium/pkg/maps/ctmap"
	"github.com/cilium/cilium/pkg/option"
)

// bpfCtCmd represents the bpf_ct command
var bpfCtCmd = &cobra.Command{
	Use:   "ct",
	Short: "Connection tracking tables",
}

func init() {
	ctmap.InitMapInfo(option.CTMapEntriesGlobalTCPDefault, option.CTMapEntriesGlobalAnyDefault, true, true, true)
	bpfCmd.AddCommand(bpfCtCmd)
}
