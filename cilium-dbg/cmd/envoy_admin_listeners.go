// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"strings"

	"github.com/spf13/cobra"

	"github.com/cilium/cilium/pkg/command"
)

var EnvoyAdminListenersCmd = &cobra.Command{
	Use:   "listeners",
	Short: "List configured listeners of Envoy Proxy",
	Run: func(cmd *cobra.Command, args []string) {
		envoyAdminClient := newEnvoyAdminClient()

		listeners, err := envoyAdminClient.GetListeners(strings.ToLower(command.OutputOptionString()))
		if err != nil {
			Fatalf("cannot get listeners: %s\n", err)
		}

		cmd.Println(listeners)
	},
}

func init() {
	EnvoyAdminCmd.AddCommand(EnvoyAdminListenersCmd)
	command.AddOutputOption(EnvoyAdminListenersCmd)
}
