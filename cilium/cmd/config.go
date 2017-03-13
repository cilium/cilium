// Copyright 2017 Authors of Cilium
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
	"os"
	"sort"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/common"
	"github.com/cilium/cilium/daemon/options"
	"github.com/cilium/cilium/pkg/option"

	"github.com/spf13/cobra"
)

// configCmd represents the config command
var configCmd = &cobra.Command{
	Use:   "config [<option>=(enable|disable) ...]",
	Short: "A brief description of your command",
	Run: func(cmd *cobra.Command, args []string) {
		if listOptions {
			for k, s := range options.Library {
				fmt.Printf("%-24s %s\n", k, s.Description)
			}
			return
		}

		configDaemon(cmd, args)
	},
}

func init() {
	RootCmd.AddCommand(configCmd)
	configCmd.Flags().BoolVarP(&listOptions, "list-options", "", false, "List available options")
}

func dumpConfig(Opts map[string]string) {
	opts := []string{}
	for k := range Opts {
		opts = append(opts, k)
	}
	sort.Strings(opts)

	for _, k := range opts {
		if enabled, err := option.NormalizeBool(Opts[k]); err != nil {
			Fatalf("Invalid option answer %s: %s", Opts[k], err)
		} else if enabled {
			fmt.Printf("%-24s %s\n", k, common.Green("Enabled"))
		} else {
			fmt.Printf("%-24s %s\n", k, common.Red("Disabled"))
		}
	}
}

func configDaemon(cmd *cobra.Command, opts []string) {
	if len(opts) == 0 {
		resp, err := client.ConfigGet()
		if err != nil {
			Fatalf("Error while retrieving configuration: %s", err)
		}

		dumpConfig(resp.Configuration.Immutable)
		dumpConfig(resp.Configuration.Mutable)
		return
	}

	dOpts := make(models.ConfigurationMap, len(opts))

	for k := range opts {
		name, value, err := options.Parse(opts[k])
		if err != nil {
			fmt.Printf("%s\n", err)
			os.Exit(1)
		}

		if value {
			dOpts[name] = "Enabled"
		} else {
			dOpts[name] = "Disabled"
		}
	}

	if err := client.ConfigPatch(dOpts); err != nil {
		Fatalf("Unable to change agent configuration: %s\n", err)
	}
}
