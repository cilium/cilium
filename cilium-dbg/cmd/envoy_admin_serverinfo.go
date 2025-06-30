// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"github.com/spf13/cobra"
)

var EnvoyAdminServerinfoCmd = &cobra.Command{
	Use:   "serverinfo",
	Short: "View server info of Envoy Proxy",
	Run: func(cmd *cobra.Command, args []string) {
		envoyAdminClient := newEnvoyAdminClient()

		serverInfo, err := envoyAdminClient.GetServerInfo()
		if err != nil {
			Fatalf("cannot get server info: %s\n", err)
		}

		cmd.Println(serverInfo)
	},
}

func init() {
	EnvoyAdminCmd.AddCommand(EnvoyAdminServerinfoCmd)
}
