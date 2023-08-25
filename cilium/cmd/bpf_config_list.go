// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/cilium/cilium/pkg/command"
	"github.com/cilium/cilium/pkg/common"
	"github.com/cilium/cilium/pkg/maps/configmap"
)

type configEntry struct {
	Key   string
	Value uint64
}

var bpfConfigListCmd = &cobra.Command{
	Use:     "list",
	Short:   "List all runtime config entries",
	Long:    "List all runtime config entries",
	Aliases: []string{"ls"},
	Run: func(cmd *cobra.Command, args []string) {
		common.RequireRootPrivilege("cilium bpf config list")

		configMap, err := configmap.LoadMap()
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				fmt.Fprintln(os.Stderr, "Cannot find config bpf map")
				return
			}

			Fatalf("Cannot load config bpf map: %s", err)
		}

		var entries []configEntry

		for _, index := range []configmap.Index{
			configmap.AgentLiveness,
			configmap.UTimeOffset,
		} {
			value, err := configMap.Get(index)
			if err != nil {
				Fatalf("Cannot load value with index %q from config bpf map: %s", index, err)
			}
			entries = append(entries, configEntry{Key: index.String(), Value: value})
		}

		if command.OutputOption() {
			if err := command.PrintOutput(entries); err != nil {
				Fatalf("error getting output of map in JSON: %s\n", err)
			}
			return
		}

		printEntries(entries)
	},
}

func printEntries(entries []configEntry) {
	w := tabwriter.NewWriter(os.Stdout, 5, 0, 3, ' ', 0)

	fmt.Fprintln(w, "KEY\tVALUE")
	for _, e := range entries {
		fmt.Fprintf(w, "%s\t%d\n", e.Key, e.Value)
	}
	w.Flush()
}

func init() {
	BPFConfigCmd.AddCommand(bpfConfigListCmd)
	command.AddOutputOption(bpfConfigListCmd)
}
