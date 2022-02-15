// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"github.com/spf13/cobra"
)

// identityCmd represents the identity command
var identityCmd = &cobra.Command{
	Use:   "identity",
	Short: "Manage security identities",
}

func init() {
	rootCmd.AddCommand(identityCmd)
}
