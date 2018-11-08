// Copyright 2018 Authors of Cilium
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

	"github.com/cilium/cilium/common"
	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/command"
	"github.com/cilium/cilium/pkg/maps/configmap"

	"github.com/spf13/cobra"
)

// bpfConfigGetCmd represents the bpf_config_get command
var bpfConfigGetCmd = &cobra.Command{
	Use:   "get",
	Short: "List contents of an endpoint config BPF map",
	Run: func(cmd *cobra.Command, args []string) {
		common.RequireRootPrivilege("cilium bpf config get")
		requireEndpointID(cmd, args)
		listEndpointConfigMap(args)
	},
}

func init() {
	bpfConfigCmd.AddCommand(bpfConfigGetCmd)
	command.AddJSONOutput(bpfConfigCmd)
}

func listEndpointConfigMap(args []string) {
	lbl := args[0]

	if lbl == "" {
		Fatalf("Need ID or label\n")
	}

	file := bpf.MapPath(configmap.MapNamePrefix + lbl)

	fd, err := bpf.ObjGet(file)
	if err != nil {
		Fatalf("%s\n", err)
	}
	defer bpf.ObjClose(fd)

	m, _, err := configmap.OpenMapWithName(file, configmap.MapNamePrefix+lbl)
	if err != nil {
		fmt.Printf("error opening map %s: %s\n", file, err)
		os.Exit(1)
	}

	bpfConfigGet := make(map[string][]string)
	if err := m.Map.Dump(bpfConfigGet); err != nil {
		os.Exit(1)
	}
	if err != nil {
		Fatalf("Error while opening bpf Map: %s\n", err)
	}

	fmt.Printf("bpfConfigGet: %s\n", bpfConfigGet)
	if command.OutputJSON() {
		if err := command.PrintOutput(bpfConfigCmd); err != nil {
			os.Exit(1)
		}
		return
	}

	TablePrinter("KEY", "ENDPOINT CONFIGURATION", bpfConfigGet)
}
