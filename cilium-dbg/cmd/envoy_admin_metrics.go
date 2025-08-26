// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"github.com/spf13/cobra"
)

var envoyMetricsFilterRegexFlag = ""

var EnvoyAdminMetricsCmd = &cobra.Command{
	Use:   "metrics",
	Short: "List Prometheus statistics of Envoy Proxy",
	Run: func(cmd *cobra.Command, args []string) {
		envoyAdminClient := newEnvoyAdminClient()

		metrics, err := envoyAdminClient.GetPrometheusStatistics(envoyMetricsFilterRegexFlag)
		if err != nil {
			Fatalf("cannot get metrics: %s\n", err)
		}

		cmd.Println(metrics)
	},
}

func init() {
	EnvoyAdminCmd.AddCommand(EnvoyAdminMetricsCmd)
	EnvoyAdminMetricsCmd.Flags().StringVarP(&envoyMetricsFilterRegexFlag, "filter", "f", "", "Regex that should be used to filter metrics")
}
