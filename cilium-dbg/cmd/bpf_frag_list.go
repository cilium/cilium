// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"fmt"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/command"
	"github.com/cilium/cilium/pkg/common"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/maps/fragmap"
	"github.com/cilium/cilium/pkg/u8proto"
)

type bpfFragmentEntry struct {
	ID            uint32
	Proto         u8proto.U8proto
	SourceAddress string
	DestAddress   string
}

var bpfFragListCmd = &cobra.Command{
	Use:     "list",
	Aliases: []string{"ls"},
	Short:   "List IPv4 and IPv6 fragments",
	Run: func(cmd *cobra.Command, args []string) {
		common.RequireRootPrivilege("cilium bpf frag list")

		fragMap4, err := fragmap.OpenMap4(logging.DefaultSlogLogger)
		if err != nil {
			if os.IsNotExist(err) {
				fmt.Fprintf(os.Stderr, "IPv4 map doesn't exist, skipping\n")
			} else {
				Fatalf("failed to open IPv4 map: %s\n", err)
			}
		} else {
			defer fragMap4.Close()
		}

		fragMap6, err := fragmap.OpenMap6(logging.DefaultSlogLogger)
		if err != nil {
			if os.IsNotExist(err) {
				fmt.Fprintf(os.Stderr, "IPv6 map doesn't exist, skipping\n")
			} else {
				Fatalf("failed to open IPv6 map: %s\n", err)
			}
		} else {
			defer fragMap6.Close()
		}

		var entries []bpfFragmentEntry
		if fragMap4 != nil {
			entries = append(entries, dumpFragmentsIPv4(fragMap4)...)
		}
		if fragMap6 != nil {
			entries = append(entries, dumpFragmentsIPv6(fragMap6)...)
		}

		if command.OutputOption() {
			if err := command.PrintOutput(entries); err != nil {
				Fatalf("error getting output of map in JSON: %s\n", err)
			}
			return
		}

		if len(entries) == 0 {
			fmt.Fprintf(os.Stderr, "No entries found.\n")
			return
		}

		printBPFFragmentEntries(entries)
	},
}

func dumpFragmentsIPv4(fragMap4 *bpf.Map) []bpfFragmentEntry {
	var entries []bpfFragmentEntry

	if err := fragMap4.DumpWithCallback(func(k bpf.MapKey, v bpf.MapValue) {
		key := k.(*fragmap.FragmentKey4)
		value := v.(*fragmap.FragmentValue4)
		entries = append(entries, bpfFragmentEntry{
			ID:            uint32(key.NativeID()),
			Proto:         u8proto.U8proto(key.Proto),
			SourceAddress: fmt.Sprintf("%s:%d", key.SourceAddr, value.SourcePort),
			DestAddress:   fmt.Sprintf("%s:%d", key.DestAddr, value.DestPort),
		})
	}); err != nil {
		Fatalf("failed to dump contents of IPv4 map: %s\n", err)
	}

	return entries
}

func dumpFragmentsIPv6(fragMap6 *bpf.Map) []bpfFragmentEntry {
	var entries []bpfFragmentEntry

	if err := fragMap6.DumpWithCallback(func(k bpf.MapKey, v bpf.MapValue) {
		key := k.(*fragmap.FragmentKey6)
		value := v.(*fragmap.FragmentValue6)
		entries = append(entries, bpfFragmentEntry{
			ID:            key.NativeID(),
			Proto:         u8proto.U8proto(key.Proto),
			SourceAddress: fmt.Sprintf("%s:%d", key.SourceAddr, value.SourcePort),
			DestAddress:   fmt.Sprintf("[%s]:%d", key.DestAddr, value.DestPort),
		})
	}); err != nil {
		Fatalf("failed to dump contents of IPv6 map: %s\n", err)
	}

	return entries
}

func printBPFFragmentEntries(entries []bpfFragmentEntry) {
	w := tabwriter.NewWriter(os.Stdout, 5, 0, 3, ' ', 0)

	headers := []string{"ID", "PROTO", "SOURCE ADDRESS:PORT", "DEST ADDRESS:PORT"}
	fmt.Fprintln(w, strings.Join(headers, "\t"))

	for _, entry := range entries {
		fmt.Fprintf(w, "%d\t%s\t%s\t%s\n",
			entry.ID,
			entry.Proto,
			entry.SourceAddress,
			entry.DestAddress,
		)
	}

	w.Flush()
}

func init() {
	BPFFragCmd.AddCommand(bpfFragListCmd)
	command.AddOutputOption(bpfFragListCmd)
}
