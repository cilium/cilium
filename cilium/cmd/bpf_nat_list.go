// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"fmt"
	"os"
	"reflect"
	"strconv"

	"github.com/spf13/cobra"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/command"
	"github.com/cilium/cilium/pkg/common"
	"github.com/cilium/cilium/pkg/maps/nat"
	"github.com/cilium/cilium/pkg/option"
)

// bpfNatListCmd represents the bpf_nat_list command
var bpfNatListCmd = &cobra.Command{
	Use:     "list [cluster <cluster id>]",
	Aliases: []string{"ls"},
	Short:   "List all NAT mapping entries",
	Run: func(cmd *cobra.Command, args []string) {
		common.RequireRootPrivilege("cilium bpf nat list")
		if len(args) == 0 {
			ipv4, ipv6 := nat.GlobalMaps(true, getIpv6EnableStatus(), true)
			globalMaps := make([]interface{}, 2)
			globalMaps[0] = ipv4
			globalMaps[1] = ipv6
			dumpNat(globalMaps)
		} else if len(args) == 2 && args[0] == "cluster" {
			err := nat.InitPerClusterNATMaps(nat.PerClusterNATOuterMapPrefix, true, getIpv6EnableStatus(), option.LimitTableMax)
			if err != nil {
				cmd.PrintErrf("Failed to initialize per-cluster SNAT maps: %s\n", err.Error())
				return
			}
			clusterID, err := strconv.ParseUint(args[1], 10, 32)
			if err != nil {
				cmd.PrintErrf("Invalid ClusterID: %s", err.Error())
				return
			}
			ipv4, ipv6, err := nat.ClusterMaps(uint32(clusterID), true, false)
			if err != nil {
				cmd.PrintErrf("Failed to retrieve cluster maps: %s", err.Error())
				return
			}
			clusterMaps := make([]interface{}, 2)
			clusterMaps[0] = ipv4
			clusterMaps[1] = ipv6
			dumpNat(clusterMaps)
		} else {
			cmd.PrintErr("Invalid argument")
			return
		}
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
	if command.OutputOption() {
		if err := command.PrintOutput(entries); err != nil {
			os.Exit(1)
		}
	}
}
