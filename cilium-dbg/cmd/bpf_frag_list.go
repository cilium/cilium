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
	"github.com/cilium/cilium/pkg/maps/fragmap"
	"github.com/cilium/cilium/pkg/u8proto"
)

type bpfFragmentEntry struct {
	ID            uint16
	Proto         u8proto.U8proto
	SourceAddress string
	DestAddress   string
}

var bpfFragListCmd = &cobra.Command{
	Use:     "list",
	Aliases: []string{"ls"},
	Short:   "List IPv4 datagram fragments",
	Run: func(cmd *cobra.Command, args []string) {
		common.RequireRootPrivilege("cilium bpf frag list")

		fragMap, err := fragmap.OpenMap()
		if err != nil {
			Fatalf("failed to open map: %s\n", err)
		}
		defer fragMap.Close()

		var entries []bpfFragmentEntry
		if err := fragMap.DumpWithCallback(func(k bpf.MapKey, v bpf.MapValue) {
			key := k.(*fragmap.FragmentKey)
			value := v.(*fragmap.FragmentValue)
			entries = append(entries, bpfFragmentEntry{
				ID:            key.ID,
				Proto:         u8proto.U8proto(key.Proto),
				SourceAddress: fmt.Sprintf("%s:%d", key.SourceAddr, value.SourcePort),
				DestAddress:   fmt.Sprintf("%s:%d", key.DestAddr, value.DestPort),
			})
		}); err != nil {
			Fatalf("failed to dump contents of map: %s\n", err)
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
