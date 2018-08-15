// Copyright 2018 Authors of Cilium
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
	"path"
	"text/tabwriter"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/command"

	"github.com/spf13/cobra"
)

// mapListCmd represents the map_list command
var mapListCmd = &cobra.Command{
	Use:     "list",
	Short:   "List all open BPF maps",
	Example: "cilium map list",
	Run: func(cmd *cobra.Command, args []string) {
		resp, err := client.Daemon.GetMap(nil)
		if err != nil {
			Fatalf("%s", err)
		}

		mapList := resp.Payload
		if mapList == nil {
			return
		}

		if command.OutputJSON() {
			if err := command.PrintOutput(mapList); err != nil {
				os.Exit(1)
			}
		} else if mapList.Maps != nil {
			if verbose {
				printMapListVerbose(mapList)
			} else {
				printMapList(mapList)
			}
		}
	},
}

func printMapListVerbose(mapList *models.BPFMapList) {
	for _, m := range mapList.Maps {
		fmt.Printf("## Map: %s\n", path.Base(m.Path))
		printMapEntries(m)
		fmt.Printf("\n")
	}
}

func printMapList(mapList *models.BPFMapList) {
	w := tabwriter.NewWriter(os.Stdout, 5, 0, 3, ' ', 0)
	fmt.Fprintf(w, "Name\tNum entries\tNum errors\tCache enabled\n")
	for _, m := range mapList.Maps {
		entries, errors := 0, 0
		cacheEnabled := m.Cache != nil

		for _, e := range m.Cache {
			if e != nil {
				if e.LastError != "" {
					errors++
				}
				entries++
			}
		}
		fmt.Fprintf(w, "%s\t%d\t%d\t%t\n",
			path.Base(m.Path), entries, errors, cacheEnabled)
	}
	w.Flush()
}

func init() {
	mapCmd.AddCommand(mapListCmd)
	command.AddJSONOutput(mapListCmd)
	mapListCmd.Flags().BoolVar(&verbose, "verbose", false, "Print cache contents of all maps")
}
