// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"github.com/spf13/cobra"
)

// EndpointCmd represents the endpoint command
var EndpointCmd = &cobra.Command{
	Use:   "endpoint",
	Short: "Manage endpoints",
}

func init() {
	RootCmd.AddCommand(EndpointCmd)
}
