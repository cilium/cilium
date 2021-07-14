// SPDX-License-Identifier: Apache-2.0
// Copyright 2020 Authors of Cilium

package cmd

import (
	"github.com/spf13/cobra"
)

var bpfmountFSCmd = &cobra.Command{
	Use:   "fs",
	Short: "BPF filesystem mount",
}

func init() {
	bpfCmd.AddCommand(bpfmountFSCmd)
}
