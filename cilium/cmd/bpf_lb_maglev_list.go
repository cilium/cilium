// Copyright 2020 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package cmd

import (
	"fmt"
	"unsafe"

	"github.com/spf13/cobra"

	"github.com/cilium/cilium/pkg/bpf"
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

		lookupTables := map[string][]string{}
		dumpMaglevTables(lookupTables)

		if command.OutputJSON() {
			if err := command.PrintOutput(lookupTables); err != nil {
				Fatalf("Unable to generate JSON output: %s", err)
			}
			return
		}

		TablePrinter("SVC ID", "LOOKUP TABLE", lookupTables)
	},
}

var lookupTableSize = 0

func parseMaglevEntry(key bpf.MapKey, value bpf.MapValue, tables map[string][]string) {
	k := key.(*lbmap.MaglevOuterKey)
	v := value.(*lbmap.MaglevOuterVal)

	// Determine lookup table size by inspecting the first inner map
	if lookupTableSize == 0 {
		fd, err := bpf.MapFdFromID(int(v.FD))
		if err != nil {
			Fatalf("Unable to get map fd by id %d: %s", v.FD, err)
		}
		m, err := bpf.GetMapInfoByFd(uint32(fd))
		if err != nil {
			Fatalf("Unable to get map info by fd %d: %s", fd, err)
		}
		lookupTableSize = int(m.ValueSize) / 2
	}

	table := make([]uint16, lookupTableSize)
	zero := uint32(0)
	fd, err := bpf.MapFdFromID(int(v.FD))
	if err != nil {
		Fatalf("Unable to get map fd by id %d: %s", v.FD, err)
	}
	if err := bpf.LookupElement(int(fd), unsafe.Pointer(&zero), unsafe.Pointer(&table[0])); err != nil {
		Fatalf("Unable to lookup element in map by fd %d: %s", fd, err)
	}
	tables[k.ToNetwork().String()] = []string{fmt.Sprintf("%v", table)}
}

func dumpMaglevTables(tables map[string][]string) {
	parse := func(key bpf.MapKey, value bpf.MapValue) {
		parseMaglevEntry(key, value, tables)
	}

	for _, name := range []string{lbmap.MaglevOuter4MapName, lbmap.MaglevOuter6MapName} {
		// We cannot directly access the maps via lbmap.MaglevOuter{4,6}Map, as
		// both are not initialized, and they cannot be initialized due to
		// option.Config.MaglevTableSize not set in the cilium cli. Thus, we need
		// to open map with the lower-level helper and set the fields required
		// for the maps traversal.
		if m, err := bpf.OpenMap(name); err != nil {
			continue
		} else {
			m.MapKey = &lbmap.MaglevOuterKey{}
			m.MapValue = &lbmap.MaglevOuterVal{}
			m.DumpParser = bpf.ConvertKeyValue
			if err := m.DumpWithCallbackIfExists(parse); err != nil {
				Fatalf("Unable to dump %s: %s", name, err)
			}
		}
	}
}

func init() {
	bpfMaglevCmd.AddCommand(bpfMaglevListCmd)
	command.AddJSONOutput(bpfMaglevListCmd)
}
