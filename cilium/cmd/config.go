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
	"os"
	"strconv"
	"strings"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/command"
	"github.com/cilium/cilium/pkg/option"

	"github.com/spf13/cobra"
)

var numPages int

// configCmd represents the config command
var configCmd = &cobra.Command{
	Use:   "config [<option>=(enable|disable) ...]",
	Short: "Cilium configuration options",
	Run: func(cmd *cobra.Command, args []string) {
		if listOptions {
			for k, s := range option.DaemonMutableOptionLibrary {
				fmt.Printf("%-24s %s\n", k, s.Description)
			}
			return
		}

		configDaemon(cmd, args)
	},
}

func init() {
	rootCmd.AddCommand(configCmd)
	configCmd.Flags().BoolVarP(&listOptions, "list-options", "", false, "List available options")
	configCmd.Flags().IntVarP(&numPages, "num-pages", "n", 0, "Number of pages for perf ring buffer. New values have to be > 0")
	command.AddJSONOutput(configCmd)
}

func configDaemon(cmd *cobra.Command, opts []string) {
	dOpts := make(models.ConfigurationMap, len(opts))

	resp, err := client.ConfigGet()
	if err != nil {
		Fatalf("Error while retrieving configuration: %s", err)
	}
	if resp.Status == nil {
		Fatalf("Empty configuration status returned")
	}

	cfgStatus := resp.Status
	if numPages > 0 {
		if cfgStatus.NodeMonitor != nil && numPages != int(cfgStatus.NodeMonitor.Npages) {
			dOpts["MonitorNumPages"] = strconv.Itoa(numPages)
		}
	} else if len(opts) == 0 {
		if command.OutputJSON() {
			if err := command.PrintOutput(cfgStatus.Realized.Options); err != nil {
				os.Exit(1)
			}
			return
		}
		dumpConfig(cfgStatus.Immutable)
		dumpConfig(cfgStatus.Realized.Options)
		fmt.Printf("%-24s %s\n", "k8s-configuration", cfgStatus.K8sConfiguration)
		fmt.Printf("%-24s %s\n", "k8s-endpoint", cfgStatus.K8sEndpoint)
		fmt.Printf("%-24s %s\n", "PolicyEnforcement", cfgStatus.Realized.PolicyEnforcement)
		if cfgStatus.NodeMonitor != nil {
			fmt.Printf("%-24s %d\n", "MonitorNumPages", cfgStatus.NodeMonitor.Npages)
		}
		return
	}

	var cfg models.DaemonConfigurationSpec

	for k := range opts {
		// TODO FIXME - this is a hack, and is not clean
		optionSplit := strings.SplitN(opts[k], "=", 2)
		if len(optionSplit) < 2 {
			Fatalf("Improper configuration format provided")
		}
		arg := optionSplit[0]
		if arg == "PolicyEnforcement" {
			cfg.PolicyEnforcement = optionSplit[1]
			continue
		}

		name, value, err := option.ParseDaemonOption(opts[k])
		if err != nil {
			fmt.Printf("%s\n", err)
			os.Exit(1)
		}

		if opt, ok := option.DaemonMutableOptionLibrary[name]; !ok || opt.Parse == nil {
			if value == option.OptionDisabled {
				dOpts[name] = "Disabled"
			} else {
				dOpts[name] = "Enabled"
			}
		} else {
			dOpts[name] = optionSplit[1]
		}
	}

	cfg.Options = dOpts
	if err := client.ConfigPatch(cfg); err != nil {
		Fatalf("Unable to change agent configuration: %s\n", err)
	}
}
