// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"errors"
	"os"

	"github.com/spf13/cobra"

	"github.com/cilium/cilium/pkg/command"
	"github.com/cilium/cilium/pkg/common"
	"github.com/cilium/cilium/pkg/maps/lbmap"
)

// bpfMaglevListCmd represents the bpf lb maglev list command
var bpfMaglevListCmd = &cobra.Command{
	Use:     "list",
	Aliases: []string{"ls"},
	Short:   "List Maglev lookup tables",
	Run: func(cmd *cobra.Command, args []string) {
		common.RequireRootPrivilege("cilium bpf lb maglev list")

		backends, err := dumpMaglevTables()
		if err != nil {
			Fatalf("Unable to dump Maglev lookup tables: %s", err)
		}

		if command.OutputOption() {
			if err := command.PrintOutput(backends); err != nil {
				Fatalf("Unable to generate %s output: %s", command.OutputOptionString(), err)
			}
			return
		}

		TablePrinter("SVC ID", "LOOKUP TABLE", backends)
	},
}

// dumpMaglevTables returns the contents of the Maglev v4 and v6 maps
// in a format the table printer expects.
func dumpMaglevTables() (map[string][]string, error) {
	out, err := dumpMaglevTable(lbmap.MaglevOuter4MapName, false)
	if err != nil {
		return nil, err
	}

	v6, err := dumpMaglevTable(lbmap.MaglevOuter6MapName, true)
	if err != nil {
		return nil, err
	}

	// Merge v6 lookup tables into result.
	for k, v := range v6 {
		out[k] = v
	}

	return out, nil
}

// dumpMaglevTable opens the pinned Maglev map with the given name and
// dumps the backend tables of all services. Returns an empty initialized
// map if the given eBPF map does not exist.
func dumpMaglevTable(name string, ipv6 bool) (map[string][]string, error) {
	m, err := lbmap.OpenMaglevOuterMap(name)
	if errors.Is(err, os.ErrNotExist) {
		// Map not existing is not an error.
		// Skip dumping it and return an empty allocated map.
		return map[string][]string{}, nil
	}
	if err != nil {
		return nil, err
	}

	return m.DumpBackends(ipv6)
}

func init() {
	bpfMaglevCmd.AddCommand(bpfMaglevListCmd)
	command.AddOutputOption(bpfMaglevListCmd)
}
