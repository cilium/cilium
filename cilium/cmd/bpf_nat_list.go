// Copyright 2019-2020 Authors of Cilium
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

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/command"
	"github.com/cilium/cilium/pkg/common"
	"github.com/cilium/cilium/pkg/maps/nat"

	"github.com/spf13/cobra"
)

// bpfNatListCmd represents the bpf_nat_list command
var bpfNatListCmd = &cobra.Command{
	Use:     "list",
	Aliases: []string{"ls"},
	Short:   "List all NAT mapping entries",
	Run: func(cmd *cobra.Command, args []string) {
		common.RequireRootPrivilege("cilium bpf nat list")
		ipv4, ipv6 := nat.GlobalMaps(true, true)
		globalMaps := make([]interface{}, 2)
		globalMaps[0] = ipv4
		globalMaps[1] = ipv6
		dumpNat(globalMaps)
	},
}

func init() {
	bpfNatCmd.AddCommand(bpfNatListCmd)
	command.AddJSONOutput(bpfNatListCmd)
}

func dumpNat(maps []interface{}, args ...interface{}) {
	entries := make([]nat.NatMapRecord, 0)

	for _, m := range maps {
		if m == nil {
			continue
		}
		path, err := m.(nat.NatMap).Path()
		if err == nil {
			err = m.(nat.NatMap).Open()
		}
		if err != nil {
			if os.IsNotExist(err) {
				fmt.Fprintf(os.Stderr, "Unable to open %s: %s. Skipping.\n", path, err)
				continue
			}
			Fatalf("Unable to open %s: %s", path, err)
		}
		defer m.(nat.NatMap).Close()
		// Plain output prints immediately, JSON output holds until it
		// collected values from all maps to have one consistent object
		if command.OutputJSON() {
			callback := func(key bpf.MapKey, value bpf.MapValue) {
				record := nat.NatMapRecord{Key: key.(nat.NatKey), Value: value.(nat.NatEntry)}
				entries = append(entries, record)
			}
			if err = m.(nat.NatMap).DumpWithCallback(callback); err != nil {
				Fatalf("Error while collecting BPF map entries: %s", err)
			}
		} else {
			out, err := m.(nat.NatMap).DumpEntries()
			if err != nil {
				Fatalf("Error while dumping BPF Map: %s", err)
			}
			fmt.Println(out)
		}
	}
	if command.OutputJSON() {
		if err := command.PrintOutput(entries); err != nil {
			os.Exit(1)
		}
	}
}
