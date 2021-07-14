// SPDX-License-Identifier: Apache-2.0
// Copyright 2017 Authors of Cilium

package cmd

import (
	"github.com/cilium/cilium/pkg/maps/ctmap"
	"github.com/cilium/cilium/pkg/option"
	"github.com/spf13/cobra"
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
