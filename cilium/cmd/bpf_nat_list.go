// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"fmt"
	"os"
	"reflect"

	"github.com/spf13/cobra"

	bpfTypes "github.com/cilium/cilium/pkg/bpf/types"
	"github.com/cilium/cilium/pkg/command"
	"github.com/cilium/cilium/pkg/common"
	"github.com/cilium/cilium/pkg/maps/nat"
)

// bpfNatListCmd represents the bpf_nat_list command
var bpfNatListCmd = &cobra.Command{
	Use:     "list",
	Aliases: []string{"ls"},
	Short:   "List all NAT mapping entries",
	Run: func(cmd *cobra.Command, args []string) {
		common.RequireRootPrivilege("cilium bpf nat list")
		ipv4, ipv6 := nat.GlobalMaps(true, getIpv6EnableStatus(), true)
		globalMaps := make([]interface{}, 2)
		globalMaps[0] = ipv4
		globalMaps[1] = ipv6
		dumpNat(globalMaps)
	},
}

func init() {
	bpfNatCmd.AddCommand(bpfNatListCmd)
	command.AddOutputOption(bpfNatListCmd)
}

func dumpNat(maps []interface{}, args ...interface{}) {
	entries := make([]nat.NatMapRecord, 0)

	for _, m := range maps {
		if m == nil || reflect.ValueOf(m).IsNil() {
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
		// Plain output prints immediately, JSON/YAML output holds until it
		// collected values from all maps to have one consistent object
		if command.OutputOption() {
			callback := func(key bpfTypes.MapKey, value bpfTypes.MapValue) {
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
	if command.OutputOption() {
		if err := command.PrintOutput(entries); err != nil {
			os.Exit(1)
		}
	}
}
