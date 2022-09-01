// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/spf13/cobra"

	"github.com/cilium/cilium/pkg/command"
	"github.com/cilium/cilium/test/helpers"
)

var (
	removeHyphen = regexp.MustCompile(`[^\w]`)
)

// configGetCmd represents the config get command
var configGetCmd = &cobra.Command{
	Use:    "get <config name>",
	Short:  "Retrieve cilium configuration",
	PreRun: requireConfigName,
	Run: func(cmd *cobra.Command, args []string) {
		// removing hyphen from the config name and transforming it to lower case
		configName := removeHyphen.ReplaceAllString(strings.ToLower(args[0]), "")
		resp, err := client.ConfigGet()
		if err != nil {
			Fatalf("Error while retrieving configuration: %s", err)
		}
		if resp.Status == nil {
			Fatalf("Empty configuration status returned")
		}

		readWriteConfigMap := make(map[string]interface{})
		readOnlyConfigMap := resp.Status.DaemonConfigurationMap

		for k, v := range resp.Status.Realized.Options {
			readWriteConfigMap[k] = v
		}
		readWriteConfigMap[helpers.PolicyEnforcement] = resp.Status.Realized.PolicyEnforcement

		// Key values are named as field names of `DaemonConfig` struct
		// to match configuration input, map keys are transformed to lower case
		readWriteConfigMap = mapKeysToLowerCase(readWriteConfigMap)
		readOnlyConfigMap = mapKeysToLowerCase(readOnlyConfigMap)

		// conifgMap holds both read-only and read-write configurations
		configMap := mergeMaps(readOnlyConfigMap, readWriteConfigMap)

		if value, ok := configMap[configName]; ok {
			fmt.Printf("%v\n", value)
		} else {
			Fatalf("Configuration does not exist")
		}
	},
}

func init() {
	configCmd.AddCommand(configGetCmd)
	command.AddOutputOption(configGetCmd)
}

func requireConfigName(cmd *cobra.Command, args []string) {
	if len(args) < 1 {
		Usagef(cmd, "Missing config name argument")
	}

	if args[0] == "" {
		Usagef(cmd, "Empty config argument")
	}
}
