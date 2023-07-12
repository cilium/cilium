// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"github.com/spf13/cobra"
)

// CncryptCmd represents the encrypt command
var CncryptCmd = &cobra.Command{
	Use:   "encrypt",
	Short: "Manage transparent encryption",
}

func init() {
	RootCmd.AddCommand(CncryptCmd)
}
