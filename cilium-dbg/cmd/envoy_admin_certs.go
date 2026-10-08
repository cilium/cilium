// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"github.com/spf13/cobra"
)

var EnvoyAdminCertsCmd = &cobra.Command{
	Use:   "certs",
	Short: "List configured TLS certificates of Envoy Proxy",
	Run: func(cmd *cobra.Command, args []string) {
		envoyAdminClient := newEnvoyAdminClient()

		certs, err := envoyAdminClient.GetCerts()
		if err != nil {
			Fatalf("cannot get certificates: %s\n", err)
		}

		cmd.Println(certs)
	},
}

func init() {
	EnvoyAdminCmd.AddCommand(EnvoyAdminCertsCmd)
}
