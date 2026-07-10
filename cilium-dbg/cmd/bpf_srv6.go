// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"github.com/spf13/cobra"
)

// BPFSRv6Cmd represents the bpf command
var BPFSRv6Cmd = &cobra.Command{
	Use:   "srv6",
	Short: "Manage the SRv6 routing rules",
}

func init() {
	BPFCmd.AddCommand(BPFSRv6Cmd)
}
