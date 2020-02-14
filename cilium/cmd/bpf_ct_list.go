// Copyright 2017-2018 Authors of Cilium
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
		if command.OutputJSON() {
			if err := command.PrintOutput(m); err != nil {
				os.Exit(1)
			}
		} else {
			out, err := m.DumpEntries()
			if err != nil {
				Fatalf("Error while dumping BPF Map: %s", err)
			}
			fmt.Println(out)
		}
	}
}
