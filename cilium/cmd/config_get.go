// Copyright 2021 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package cmd

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/cilium/cilium/pkg/command"
	"github.com/cilium/cilium/test/helpers"
	"github.com/spf13/cobra"
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
	command.AddJSONOutput(configGetCmd)
}

func requireConfigName(cmd *cobra.Command, args []string) {
	if len(args) < 1 {
		Usagef(cmd, "Missing config name argument")
	}

	if args[0] == "" {
		Usagef(cmd, "Empty config argument")
	}
}
