// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"github.com/spf13/cobra"
)

var bpfEndpointCmd = &cobra.Command{
	Use:   "endpoint",
	Short: "Local endpoint map",
}

func init() {
	bpfCmd.AddCommand(bpfEndpointCmd)
}
