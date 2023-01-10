// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

// pingCmd represents the ping command
var pingCmd = &cobra.Command{
	Use:   "ping",
	Short: "Check whether the cilium-health API is up",
	Run: func(cmd *cobra.Command, args []string) {
		_, err := client.Restapi.GetHealthz(nil)
		if err != nil {
			Fatalf("Cannot ping: %s\n", err)
		}
		fmt.Println("OK")
	},
}

func init() {
	rootCmd.AddCommand(pingCmd)
}
