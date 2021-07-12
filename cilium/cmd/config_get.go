// Copyright 2017-2018 Authors of Cilium
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

	"github.com/cilium/cilium/pkg/command"
	"github.com/iancoleman/strcase"
	"github.com/spf13/cobra"
)

// configGetCmd represents the config get command
var configGetCmd = &cobra.Command{
	Use:    "get <config name>",
	Short:  "Retrieve cilium configuration",
	PreRun: requireConfigName,
	Run: func(cmd *cobra.Command, args []string) {
		configName := strcase.ToSnake(args[0])
		resp, err := client.ConfigGet()
		if err != nil {
			Fatalf("Error while retrieving configuration: %s", err)
		}
		if resp.Status == nil {
			Fatalf("Empty configuration status returned")
		}

		cfgStatusMap := resp.Status.DaemonConfigurationMap
		configMap := mapKeysToSnakeCase(cfgStatusMap)
		if id, ok := configMap[configName]; ok {
			fmt.Printf("%v\n", id)
		} else {
			fmt.Printf("Configuration does not exist\n")
		}
	},
}

func init() {
	configCmd.AddCommand(configGetCmd)
	command.AddJSONOutput(configGetCmd)
}
