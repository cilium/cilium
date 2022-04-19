// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"fmt"
	"os"
	"path"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/command"
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

		if command.OutputOption() {
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
	command.AddOutputOption(mapListCmd)
	mapListCmd.Flags().BoolVar(&verbose, "verbose", false, "Print cache contents of all maps")
}
