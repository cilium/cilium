// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"github.com/spf13/cobra"
)

// BPFMaglevCmd represents the bpf lb maglev command
var BPFMaglevCmd = &cobra.Command{
	Use:   "maglev",
	Short: "Maglev lookup table",
}

func init() {
	BPFLBCmd.AddCommand(BPFMaglevCmd)
}
