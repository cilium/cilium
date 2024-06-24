// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/cilium/cilium/pkg/command"
	endpointid "github.com/cilium/cilium/pkg/endpoint/id"
	"github.com/cilium/cilium/pkg/option"
)

var listOptions bool

// endpointConfigCmd represents the endpoint_config command
var endpointConfigCmd = &cobra.Command{
	Use:     "config <endpoint id> [<option>=(enable|disable) ...]",
	Short:   "View & modify endpoint configuration",
	Example: "endpoint config 5421 DropNotification=false TraceNotification=false PolicyVerdictNotification=true",
	Run: func(cmd *cobra.Command, args []string) {
		if listOptions {
			listEndpointOptions()
			return
		}

		requireEndpointID(cmd, args)
		configEndpoint(cmd, args)
	},
}

func init() {
	EndpointCmd.AddCommand(endpointConfigCmd)
	endpointConfigCmd.Flags().BoolVarP(&listOptions, "list-options", "", false, "List available options")
	command.AddOutputOption(endpointConfigCmd)
}

var endpointMutableOptionLibrary = option.GetEndpointMutableOptionLibrary()

func listEndpointOptions() {
	for k, s := range endpointMutableOptionLibrary {
		fmt.Printf("%-24s %s\n", k, s.Description)
	}
}

func configEndpoint(cmd *cobra.Command, args []string) {
	_, id, _ := endpointid.Parse(args[0])
	cfg, err := client.EndpointConfigGet(id)
	if err != nil {
		Fatalf("Cannot get configuration of endpoint %s: %s\n", id, err)
	}

	opts := args[1:]
	if len(opts) == 0 {
		if command.OutputOption() {
			if err := command.PrintOutput(cfg); err != nil {
				os.Exit(1)
			}
			return
		}

		dumpConfig(cfg.Immutable, false)
		dumpConfig(cfg.Realized.Options, false)
		return
	}

	// modify the configuration we fetched directly since we don't need it
	modifiedOptsCfg := cfg.Realized
	for k := range opts {
		name, value, err := endpointMutableOptionLibrary.ParseOption(opts[k])
		if err != nil {
			Fatalf("Cannot parse option %s: %s", opts[k], err)
		}
		modifiedOptsCfg.Options[name] = fmt.Sprintf("%d", value)
	}

	err = client.EndpointConfigPatch(id, modifiedOptsCfg)
	if err != nil {
		Fatalf("Cannot update endpoint %s: %s", id, err)
	}

	fmt.Printf("Endpoint %s configuration updated successfully\n", id)
}
