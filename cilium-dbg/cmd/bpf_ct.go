// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"github.com/spf13/cobra"

	"github.com/cilium/cilium/pkg/maps/ctmap"
	"github.com/cilium/cilium/pkg/maps/nat"
)

// BPFCtCmd represents the bpf_ct command
var BPFCtCmd = &cobra.Command{
	Use:   "ct",
	Short: "Connection tracking tables",
}

func init() {
	nat4, nat6 := nat.GlobalMaps(nil, true, true)
	ctmap.InitMapInfo(nil, true, true, nat4, nat6)
	BPFCmd.AddCommand(BPFCtCmd)
}
