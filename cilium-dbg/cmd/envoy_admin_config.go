// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"fmt"
	"maps"
	"slices"
	"strings"

	"github.com/spf13/cobra"
)

var envoyResourceNameFlag = ""

var envoyResourceTypeMappings = map[string]string{
	"all":             "",
	"listeners":       "dynamic_listeners",
	"routes":          "dynamic_route_configs",
	"clusters":        "dynamic_active_clusters",
	"endpoints":       "dynamic_endpoint_configs",
	"secrets":         "dynamic_active_secrets",
	"networkpolicies": "networkpolicies",
}

var EnvoyAdminConfigCmd = &cobra.Command{
	Use:       fmt.Sprintf("config %s", envoyResourceTypeOptionsString()),
	Short:     "View config dump of Envoy Proxy",
	Args:      cobra.OnlyValidArgs,
	ValidArgs: slices.Collect(maps.Keys(envoyResourceTypeMappings)),
	Run: func(cmd *cobra.Command, args []string) {
		resourceType := "all"
		if len(args) > 0 {
			resourceType = args[0]
		}

		envoyAdminClient := newEnvoyAdminClient()

		configDump, err := envoyAdminClient.GetConfigDump(envoyResourceTypeMappings[resourceType], envoyResourceNameFlag)
		if err != nil {
			Fatalf("cannot get config dump: %s\n", err)
		}

		cmd.Println(configDump)
	},
}

func init() {
	EnvoyAdminCmd.AddCommand(EnvoyAdminConfigCmd)
	EnvoyAdminConfigCmd.Flags().StringVarP(&envoyResourceNameFlag, "name", "n", "", "Regex that should be used to filter resource names")
}

func envoyResourceTypeOptionsString() string {
	return fmt.Sprintf("[ %s ]", strings.Join(slices.Sorted(maps.Keys(envoyResourceTypeMappings)), " | "))
}
