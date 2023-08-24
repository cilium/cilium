// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"github.com/spf13/cobra"
)

var BPFMountFSCmd = &cobra.Command{
	Use:   "fs",
	Short: "BPF filesystem mount",
}

func init() {
	BPFCmd.AddCommand(BPFMountFSCmd)
}
