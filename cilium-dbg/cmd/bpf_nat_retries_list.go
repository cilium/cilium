// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/command"
	"github.com/cilium/cilium/pkg/common"
	"github.com/cilium/cilium/pkg/maps/nat"
)

// bpfNatRetriesListCmd represents the bpf_nat_retries_list command
var bpfNatRetriesListCmd = &cobra.Command{
	Use:     "list",
	Aliases: []string{"ls"},
	Short:   "Show the NAT retries histogram",
	Run: func(cmd *cobra.Command, args []string) {
		common.RequireRootPrivilege("cilium bpf nat retries list")
		if len(args) != 0 {
			cmd.PrintErr("Invalid argument")
			return
		}

		ipv4, ipv6 := nat.RetriesMaps(true, getIpv6EnableStatus(), true)
		if ipv4 != nil {
			dumpRetries(ipv4)
		}
		if ipv6 != nil {
			dumpRetries(ipv6)
		}
	},
}

func init() {
	BPFNatRetriesCmd.AddCommand(bpfNatRetriesListCmd)
	command.AddOutputOption(bpfNatRetriesListCmd)
}

func dumpRetries(m nat.RetriesMap) {
	path, err := m.Path()
	if err == nil {
		err = m.Open()
	}
	if err != nil {
		if os.IsNotExist(err) {
			fmt.Fprintf(os.Stderr, "Unable to open %s: %s. Skipping.\n", path, err)
			return
		}
		Fatalf("Unable to open %s: %s", path, err)
	}
	defer m.Close()

	var entries []nat.RetriesMapRecord
	var histogram = make([]uint32, nat.SnatCollisionRetries+1)
	callback := func(key bpf.MapKey, values any) {
		var sum uint32
		for _, v := range *values.(*nat.RetriesValues) {
			sum += v.Value
		}
		record := nat.RetriesMapRecord{Key: key.(*nat.RetriesKey), Value: &nat.RetriesValue{Value: sum}}
		entries = append(entries, record)
		histogram[key.(*nat.RetriesKey).Key] = sum
	}
	if err = m.DumpPerCPUWithCallback(callback); err != nil {
		Fatalf("Error while collecting BPF map entries: %s", err)
	}

	if command.OutputOption() {
		if err := command.PrintOutput(entries); err != nil {
			os.Exit(1)
		}
	} else {
		for k, v := range histogram {
			fmt.Fprintf(os.Stdout, "%d:\t%d\n", k, v)
		}
	}
}
