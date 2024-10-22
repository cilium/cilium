// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"github.com/spf13/cobra"
)

// IdentityCmd represents the identity command
var IdentityCmd = &cobra.Command{
	Use:   "identity",
	Short: "Manage security identities",
}

func init() {
	RootCmd.AddCommand(IdentityCmd)
}
