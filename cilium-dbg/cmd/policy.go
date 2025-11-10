// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"github.com/spf13/cobra"
)

// PolicyCmd represents the policy command
var PolicyCmd = &cobra.Command{
	Use:   "policy",
	Short: "Manage security policies",
}

func init() {
	RootCmd.AddCommand(PolicyCmd)
}
