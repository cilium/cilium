// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/command"
	"github.com/cilium/cilium/pkg/common"
	"github.com/cilium/cilium/pkg/maps/lbmap"
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

		// Initialize the LB maps
		lbmap.Init(lbmap.InitParams{IPv4: true, IPv6: true})

		entries := make(map[string][]string)
		dumpReverseSKEntries(entries)

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

func dumpReverseSKEntries(entries map[string][]string) {
	// Dump IPv4 entries
	parseV4Entry := func(key bpf.MapKey, value bpf.MapValue) {
		k := key.(*lbmap.SockRevNat4Key)
		v := value.(*lbmap.SockRevNat4Value)

		cookie := fmt.Sprintf("%d", k.Cookie)
		entry := fmt.Sprintf("%s:%d -> %s:%d (revnat=%d)",
			k.Address.String(), k.Port,
			v.Address.String(), v.Port,
			v.RevNatIndex)

		entries[cookie] = append(entries[cookie], entry)
	}

	if err := lbmap.SockRevNat4Map.DumpWithCallbackIfExists(parseV4Entry); err != nil {
		Fatalf("Unable to dump IPv4 reverse NAT entries: %s", err)
	}

	// Dump IPv6 entries
	parseV6Entry := func(key bpf.MapKey, value bpf.MapValue) {
		k := key.(*lbmap.SockRevNat6Key)
		v := value.(*lbmap.SockRevNat6Value)

		cookie := fmt.Sprintf("%d", k.Cookie)
		entry := fmt.Sprintf("[%s]:%d -> [%s]:%d (revnat=%d)",
			k.Address.String(), k.Port,
			v.Address.String(), v.Port,
			v.RevNatIndex)

		entries[cookie] = append(entries[cookie], entry)
	}

	if err := lbmap.SockRevNat6Map.DumpWithCallbackIfExists(parseV6Entry); err != nil {
		Fatalf("Unable to dump IPv6 reverse NAT entries: %s", err)
	}
}

func init() {
	BPFCmd.AddCommand(bpfSocknatCmd)
	bpfSocknatCmd.AddCommand(bpfSocknatListCmd)
	command.AddOutputOption(bpfSocknatListCmd)
}
