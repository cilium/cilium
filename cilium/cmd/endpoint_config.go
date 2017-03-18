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

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/option"

	"github.com/spf13/cobra"
)

var listOptions bool

// endpointConfigCmd represents the endpoint_config command
var endpointConfigCmd = &cobra.Command{
	Use:     "config <endpoint id> [<option>=(enable|disable) ...]",
	Short:   "View & modify endpoint configuration",
	Example: "endpoint config 5421 DropNotification=disable",
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
	endpointCmd.AddCommand(endpointConfigCmd)
	endpointConfigCmd.Flags().BoolVarP(&listOptions, "list-options", "", false, "List available options")
}

func listEndpointOptions() {
	for k, s := range endpoint.EndpointOptionLibrary {
		fmt.Printf("%-24s %s\n", k, s.Description)
	}
}

func configEndpoint(cmd *cobra.Command, args []string) {
	_, id, _ := endpoint.ValidateID(args[0])
	cfg, err := client.EndpointConfigGet(id)
	if err != nil {
		Fatalf("Cannot get configuration of endpoint %s: %s\n", id, err)
	}

	opts := args[1:]
	if len(opts) == 0 {
		dumpConfig(cfg.Immutable)
		dumpConfig(cfg.Mutable)
		return
	}

	epOpts := make(models.ConfigurationMap, len(opts))

	for k := range opts {
		name, value, err := option.ParseOption(opts[k], &endpoint.EndpointOptionLibrary)
		if err != nil {
			Fatalf("Cannot parse option %s: %s", opts[k], err)
		}

		if value {
			epOpts[name] = "enabled"
		} else {
			epOpts[name] = "disabled"
		}
	}

	err = client.EndpointConfigPatch(id, epOpts)
	if err != nil {
		Fatalf("Cannot update endpoint %s: %s", id, err)
	}

	fmt.Printf("Endpoint %s configuration updated successfully\n", id)
}
