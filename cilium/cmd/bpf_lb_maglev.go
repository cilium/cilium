// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"github.com/spf13/cobra"
)

// bpfMaglevCmd represents the bpf lb maglev command
var bpfMaglevCmd = &cobra.Command{
	Use:   "maglev",
	Short: "Maglev lookup table",
}

func init() {
	bpfLBCmd.AddCommand(bpfMaglevCmd)
}
