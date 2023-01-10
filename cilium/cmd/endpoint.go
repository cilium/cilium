// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"github.com/spf13/cobra"
)

// endpointCmd represents the endpoint command
var endpointCmd = &cobra.Command{
	Use:   "endpoint",
	Short: "Manage endpoints",
}

func init() {
	rootCmd.AddCommand(endpointCmd)
}
