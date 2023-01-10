// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/spf13/cobra"

	daemonAPI "github.com/cilium/cilium/api/v1/client/daemon"
	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/api"
	"github.com/cilium/cilium/pkg/command"
)

// mapGetCmd represents the map_get command
var mapGetCmd = &cobra.Command{
	Use:     "get <name>",
	Short:   "Display cached content of given BPF map",
	Example: "cilium map get cilium_ipcache",
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) == 0 || args[0] == "" {
			Fatalf("map name must be specified")
		}

		params := daemonAPI.NewGetMapNameParams().WithName(args[0]).WithTimeout(api.ClientTimeout)

		resp, err := client.Daemon.GetMapName(params)
		if err != nil {
			Fatalf("%s", err)
		}

		m := resp.Payload
		if m == nil {
			return
		}

		if command.OutputOption() {
			if err := command.PrintOutput(m); err != nil {
				os.Exit(1)
			}
			return
		}

		printMapEntries(m)
	},
}

func printMapEntries(m *models.BPFMap) {
	if m.Cache == nil {
		fmt.Printf("Cache is disabled\n\n")
		return
	}

	if len(m.Cache) == 0 {
		fmt.Printf("Cache is empty\n\n")
		return
	}

	w := tabwriter.NewWriter(os.Stdout, 5, 0, 3, ' ', 0)
	fmt.Fprintf(w, "Key\tValue\tState\tError\n")
	for _, e := range m.Cache {
		if e != nil {
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\n",
				e.Key, e.Value, e.DesiredAction, e.LastError)
		}
	}
	w.Flush()
}

func init() {
	mapCmd.AddCommand(mapGetCmd)
	command.AddOutputOption(mapGetCmd)
}
