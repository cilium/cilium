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

func parseMaglevEntry(key *lbmap.MaglevOuterKey, value *lbmap.MaglevOuterVal, tableSize uint32, tables map[string][]string) {
	innerMap, err := lbmap.MaglevInnerMapFromID(int(value.FD), tableSize)
	if err != nil {
		Fatalf("Unable to get map fd by id %d: %s", value.FD, err)
	}

	innerKey := lbmap.MaglevInnerKey{
		Zero: 0,
	}
	innerValue, err := innerMap.Lookup(&innerKey)
	if err != nil {
		Fatalf("Unable to lookup element in map by fd %d: %s", value.FD, err)
	}

	tables[fmt.Sprintf("%d", key.ToNetwork().RevNatID)] = []string{fmt.Sprintf("%v", innerValue.BackendIDs)}
}

func dumpMaglevTables(tables map[string][]string) {
	tableSize, err := lbmap.OpenMaglevMaps()
	if err != nil {
		Fatalf("Cannot initialize maglev maps: %s", err)
	}

	parse := func(key *lbmap.MaglevOuterKey, value *lbmap.MaglevOuterVal) {
		parseMaglevEntry(key, value, tableSize, tables)
	}

	for name, m := range lbmap.GetOpenMaglevMaps() {
		if err := m.IterateWithCallback(parse); err != nil {
			Fatalf("Unable to dump %s: %v", name, err)
		}
	}
}

func init() {
	bpfMaglevCmd.AddCommand(bpfMaglevListCmd)
	command.AddJSONOutput(bpfMaglevListCmd)
}
