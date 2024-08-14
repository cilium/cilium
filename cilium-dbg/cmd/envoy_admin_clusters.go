// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"strings"

	"github.com/spf13/cobra"

	"github.com/cilium/cilium/pkg/command"
)

var EnvoyAdminClustersCmd = &cobra.Command{
	Use:   "clusters",
	Short: "List configured clusters of Envoy Proxy",
	Run: func(cmd *cobra.Command, args []string) {
		envoyAdminClient := newEnvoyAdminClient()

		clusters, err := envoyAdminClient.GetClusters(strings.ToLower(command.OutputOptionString()))
		if err != nil {
			Fatalf("cannot get clusters: %s\n", err)
		}

		cmd.Println(clusters)
	},
}

func init() {
	EnvoyAdminCmd.AddCommand(EnvoyAdminClustersCmd)
	command.AddOutputOption(EnvoyAdminClustersCmd)
}
