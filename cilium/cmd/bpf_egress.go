// SPDX-License-Identifier: Apache-2.0
// Copyright 2021 Authors of Cilium

package cmd

import (
	"github.com/spf13/cobra"
)

// bpfEgressCmd represents the bpf command
var bpfEgressCmd = &cobra.Command{
	Use:   "egress",
	Short: "Manage the egress routing rules",
}

func init() {
	bpfCmd.AddCommand(bpfEgressCmd)
}
