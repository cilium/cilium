// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import "github.com/spf13/cobra"

// EnvoyCmd represents the envoy command
var EnvoyCmd = &cobra.Command{
	Use:   "envoy",
	Short: "Manage Envoy Proxy",
}

func init() {
	RootCmd.AddCommand(EnvoyCmd)
}
