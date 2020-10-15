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
	"errors"
	"strconv"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/command"
	"github.com/cilium/cilium/pkg/common"
	"github.com/cilium/cilium/pkg/maps/lbmap"

	"github.com/spf13/cobra"
	"golang.org/x/sys/unix"
)

var bpfMaglevGetCmd = &cobra.Command{
	Use:     "get <service id>",
	Aliases: []string{"get"},
	Short:   "Get Maglev lookup table for given service by ID",
	PreRun:  requireServiceID,
	Run: func(cmd *cobra.Command, args []string) {
		common.RequireRootPrivilege("cilium bpf lb maglev get")

		svcID, err := strconv.Atoi(args[0])
		if err != nil {
			Fatalf("Unable to parse %s: %s", args[0], err)
		}
		key := &lbmap.MaglevOuterKey{RevNatID: uint16(svcID)}
		key = key.ToNetwork()
		val := &lbmap.MaglevOuterVal{}

		lookupTables := map[string][]string{}
		found := false

		for _, name := range []string{lbmap.MaglevOuter4MapName, lbmap.MaglevOuter6MapName} {
			// See bpf_lb_maglev_list.go comment for why we use low-level routines
			// to open and access the maps
			if m, err := bpf.OpenMap(name); err != nil {
				continue
			} else {
				err := bpf.LookupElement(m.GetFd(), key.GetKeyPtr(), val.GetValuePtr())
				if err != nil {
					if errors.Is(err, unix.ENOENT) {
						continue
					}
					Fatalf("Unable to retrieve entry from %s with key %s: %s",
						name, key, err)
				} else {
					found = true
					parseMaglevEntry(key, val, lookupTables)
				}
			}
		}

		if !found {
			Fatalf("No entry for %d svc is found", svcID)
		}

		if command.OutputJSON() {
			if err := command.PrintOutput(lookupTables); err != nil {
				Fatalf("Unable to generate JSON output: %s", err)
			}
			return
		}

		TablePrinter("SVC ID", "LOOKUP TABLE", lookupTables)
	},
}

func init() {
	bpfMaglevCmd.AddCommand(bpfMaglevGetCmd)
	command.AddJSONOutput(bpfMaglevGetCmd)
}
