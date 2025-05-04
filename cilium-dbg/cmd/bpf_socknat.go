// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/command"
	"github.com/cilium/cilium/pkg/common"
	lbmap "github.com/cilium/cilium/pkg/loadbalancer/maps"
)

var bpfSocknatCmd = &cobra.Command{
	Use:   "socknat",
	Short: "Socket NAT operations",
}

var bpfSocknatListCmd = &cobra.Command{
	Use:     "list",
	Aliases: []string{"ls"},
	Short:   "List socket-LB reverse NAT entries",
	Run: func(cmd *cobra.Command, args []string) {
		common.RequireRootPrivilege("cilium bpf socknat list")

		// Create the maps directly
		sockRevNat4Map := lbmap.NewSockRevNat4Map(256 * 1024) // Default size
		sockRevNat6Map := lbmap.NewSockRevNat6Map(256 * 1024) // Default size

		entries := make(map[string][]string)
		dumpReverseSKEntries(entries, sockRevNat4Map, sockRevNat6Map)

		if command.OutputOption() {
			if err := command.PrintOutput(entries); err != nil {
				Fatalf("Unable to generate %s output: %s",
					command.OutputOptionString(), err)
			}
			return
		}

		TablePrinter("Socket Cookie", "Backend -> Frontend", entries)
	},
}

func dumpReverseSKEntries(entries map[string][]string, sockRevNat4Map, sockRevNat6Map *bpf.Map) {
	parseEntry := func(key bpf.MapKey, value bpf.MapValue) {
		var cookie string
		var entry string

		switch k := key.(type) {
		case *lbmap.SockRevNat4Key:
			if v, ok := value.(*lbmap.SockRevNat4Value); ok {
				cookie = fmt.Sprintf("%d", k.Cookie)
				entry = fmt.Sprintf("%s:%d -> %s:%d (revnat=%d)",
					k.Address.String(), k.Port,
					v.Address.String(), v.Port,
					v.RevNatIndex)
			}
		case *lbmap.SockRevNat6Key:
			if v, ok := value.(*lbmap.SockRevNat6Value); ok {
				cookie = fmt.Sprintf("%d", k.Cookie)
				entry = fmt.Sprintf("[%s]:%d -> [%s]:%d (revnat=%d)",
					k.Address.String(), k.Port,
					v.Address.String(), v.Port,
					v.RevNatIndex)
			}
		}

		if entry != "" {
			entries[cookie] = append(entries[cookie], entry)
		}
	}

	if err := sockRevNat4Map.DumpWithCallbackIfExists(parseEntry); err != nil {
		Fatalf("Unable to dump IPv4 reverse NAT entries: %s", err)
	}

	if err := sockRevNat6Map.DumpWithCallbackIfExists(parseEntry); err != nil {
		Fatalf("Unable to dump IPv6 reverse NAT entries: %s", err)
	}
}

func init() {
	BPFCmd.AddCommand(bpfSocknatCmd)
	bpfSocknatCmd.AddCommand(bpfSocknatListCmd)
	command.AddOutputOption(bpfSocknatListCmd)
}
