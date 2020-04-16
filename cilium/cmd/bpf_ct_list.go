// Copyright 2017-2020 Authors of Cilium
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
	"os"
	"strconv"

	"github.com/cilium/cilium/common"
	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/command"
	"github.com/cilium/cilium/pkg/maps/ctmap"

	"github.com/spf13/cobra"
)

// bpfCtListCmd represents the bpf_ct_list command
var bpfCtListCmd = &cobra.Command{
	Use:     "list ( <endpoint identifier> | global )",
	Aliases: []string{"ls"},
	Short:   "List connection tracking entries",
	PreRun:  requireEndpointIDorGlobal,
	Run: func(cmd *cobra.Command, args []string) {
		common.RequireRootPrivilege("cilium bpf ct list")
		dumpCt(args[0])
	},
}

func init() {
	bpfCtCmd.AddCommand(bpfCtListCmd)
	command.AddJSONOutput(bpfCtListCmd)
}

func dumpCt(eID string) {
	var maps []*ctmap.Map
	if eID == "global" {
		maps = ctmap.GlobalMaps(true, true)
	} else {
		id, _ := strconv.Atoi(eID)
		maps = ctmap.LocalMaps(&dummyEndpoint{ID: id}, true, true)
	}
	entries := make([]ctmap.CtMapRecord, 0)

	for _, m := range maps {
		path, err := m.Path()
		if err == nil {
			err = m.Open()
		}
		if err != nil {
			if os.IsNotExist(err) {
				msg := "Unable to open %s: %s."
				if eID != "global" {
					msg = "Unable to open %s: %s: please try using \"cilium bpf ct list global\"."
				}
				fmt.Fprintf(os.Stderr, msg+" Skipping.\n", path, err)
				continue
			}
			Fatalf("Unable to open %s: %s", path, err)
		}
		defer m.Close()
		// Plain output prints immediately, JSON output holds until it
		// collected values from all maps to have one consistent object
		if command.OutputJSON() {
			callback := func(key bpf.MapKey, value bpf.MapValue) {
				record := ctmap.CtMapRecord{Key: key.(ctmap.CtKey), Value: *value.(*ctmap.CtEntry)}
				entries = append(entries, record)
			}
			if err = m.DumpWithCallback(callback); err != nil {
				Fatalf("Error while collecting BPF map entries: %s", err)
			}
		} else {
			out, err := m.DumpEntries()
			if err != nil {
				Fatalf("Error while dumping BPF Map: %s", err)
			}
			fmt.Println(out)
		}
	}
	if command.OutputJSON() {
		if err := command.PrintOutput(entries); err != nil {
			os.Exit(1)
		}
	}
}
