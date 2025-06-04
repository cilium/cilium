// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"os"

	"github.com/cilium/ebpf"
	"github.com/spf13/cobra"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/byteorder"
	"github.com/cilium/cilium/pkg/command"
	"github.com/cilium/cilium/pkg/common"
	lbmaps "github.com/cilium/cilium/pkg/loadbalancer/maps"
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
	out, err := dumpMaglevTable(lbmaps.MaglevOuter4MapName, false)
	if err != nil {
		return nil, err
	}

	v6, err := dumpMaglevTable(lbmaps.MaglevOuter6MapName, true)
	if err != nil {
		return nil, err
	}

	// Merge v6 lookup tables into result.
	maps.Copy(out, v6)

	return out, nil
}

func openMaglevOuterMap(logger *slog.Logger, name string) (*ebpf.Map, error) {
	path := bpf.MapPath(logger, name)
	return ebpf.LoadPinnedMap(path, nil)
}

// dumpMaglevTable opens the pinned Maglev map with the given name and
// dumps the backend tables of all services. Returns an empty initialized
// map if the given eBPF map does not exist.
func dumpMaglevTable(name string, ipv6 bool) (map[string][]string, error) {
	m, err := openMaglevOuterMap(log, name)
	if errors.Is(err, os.ErrNotExist) {
		// Map not existing is not an error.
		// Skip dumping it and return an empty allocated map.
		return map[string][]string{}, nil
	}
	if err != nil {
		return nil, err
	}

	return dumpMaglevBackends(m, ipv6)
}

// dumpBackends iterates through all of the Maglev map's entries,
// opening each entry's inner map, and dumps their contents in a format
// expected by Cilium's table printer.
func dumpMaglevBackends(m *ebpf.Map, ipv6 bool) (map[string][]string, error) {
	var (
		out = make(map[string][]string)
		key lbmaps.MaglevOuterKey
		val lbmaps.MaglevOuterVal
	)
	which := "v4"
	if ipv6 {
		which = "v6"
	}
	iter := m.Iterate()
	for iter.Next(&key, &val) {
		inner, err := lbmaps.MaglevInnerMapFromID(val.FD)
		if err != nil {
			return nil, fmt.Errorf("cannot open inner map with id %d: %w", val.FD, err)
		}
		defer inner.Close()

		backends, err := inner.DumpBackends()
		if err != nil {
			return nil, fmt.Errorf("dumping inner map id %d: %w", val.FD, err)
		}

		// The service ID is read from the map in network byte order,
		// convert to host byte order before displaying to the user.
		key.RevNatID = byteorder.NetworkToHost16(key.RevNatID)

		out[fmt.Sprintf("[%d]/%s", key.RevNatID, which)] = []string{backends}
	}

	return out, nil
}

func init() {
	BPFMaglevCmd.AddCommand(bpfMaglevListCmd)
	command.AddOutputOption(bpfMaglevListCmd)
}
