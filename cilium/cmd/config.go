// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"fmt"
	"os"
	"reflect"
	"sort"
	"strconv"
	"strings"

	"github.com/spf13/cobra"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/command"
	"github.com/cilium/cilium/pkg/option"
)

var (
	numPages                   int
	listReadOnlyConfigurations bool
	listAllConfigurations      bool
)

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
	configCmd.Flags().BoolVarP(&listReadOnlyConfigurations, "read-only", "r", false, "Display read only configurations")
	configCmd.Flags().BoolVarP(&listAllConfigurations, "all", "a", false, "Display all cilium configurations")
	configCmd.Flags().IntVarP(&numPages, "num-pages", "n", 0, "Number of pages for perf ring buffer. New values have to be > 0")
	command.AddOutputOption(configCmd)
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
		printConfigurations(cfgStatus)
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

func printConfigurations(cfgStatus *models.DaemonConfigurationStatus) {
	if command.OutputOption() {
		if listReadOnlyConfigurations {
			if err := command.PrintOutput(cfgStatus.DaemonConfigurationMap); err != nil {
				Fatalf("Cannot show configurations: %v", err)
			}
		} else if listAllConfigurations {
			if err := command.PrintOutputWithPatch(cfgStatus.DaemonConfigurationMap, cfgStatus.Realized); err != nil {
				Fatalf("Cannot show configurations: %v", err)
			}
		} else {
			if err := command.PrintOutput(cfgStatus.Realized.Options); err != nil {
				Fatalf("Cannot show configurations: %v", err)
			}
		}
		return
	}
	if listReadOnlyConfigurations {
		dumpReadOnlyConfigs(cfgStatus)
	} else if listAllConfigurations {
		dumpReadOnlyConfigs(cfgStatus)
		dumpReadWriteConfigs(cfgStatus)
	} else {
		dumpReadWriteConfigs(cfgStatus)
	}
}

func dumpReadOnlyConfigs(cfgStatus *models.DaemonConfigurationStatus) {
	fmt.Println("#### Read-only configurations ####")
	keys := make([]string, 0, len(cfgStatus.DaemonConfigurationMap))
	for k := range cfgStatus.DaemonConfigurationMap {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		v := cfgStatus.DaemonConfigurationMap[k]
		if reflect.ValueOf(v).Kind() == reflect.Map {
			mapString := make(map[string]string)
			m, ok := v.(map[string]interface{})
			if ok {
				fmt.Println(k)
				for key, value := range m {
					mapString[key] = fmt.Sprintf("%v", value)
				}
				dumpConfig(mapString, true)
				continue
			} else {
				fmt.Fprintf(os.Stderr, "Error: cannot cast daemon config map to map[string]interface{}\n")
			}
		}
		fmt.Printf("%-34s: %v\n", k, v)
	}
	fmt.Printf("%-34s: %s\n", "k8s-configuration", cfgStatus.K8sConfiguration)
	fmt.Printf("%-34s: %s\n", "k8s-endpoint", cfgStatus.K8sEndpoint)
	dumpConfig(cfgStatus.Immutable, false)
}

func dumpReadWriteConfigs(cfgStatus *models.DaemonConfigurationStatus) {
	fmt.Println("##### Read-write configurations #####")
	dumpConfig(cfgStatus.Realized.Options, false)
	if cfgStatus.NodeMonitor != nil {
		fmt.Printf("%-34s: %d\n", "MonitorNumPages", cfgStatus.NodeMonitor.Npages)
	}
	fmt.Printf("%-34s: %s\n", "PolicyEnforcement", cfgStatus.Realized.PolicyEnforcement)
}
