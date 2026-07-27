// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"github.com/spf13/cobra"
)

var BPFEndpointCmd = &cobra.Command{
	Use:   "endpoint",
	Short: "Local endpoint map",
}

func init() {
	BPFCmd.AddCommand(BPFEndpointCmd)
}
