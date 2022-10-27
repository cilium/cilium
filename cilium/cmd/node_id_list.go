// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/spf13/cobra"

	daemonApi "github.com/cilium/cilium/api/v1/client/daemon"
	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/api"
	pkg "github.com/cilium/cilium/pkg/client"
	"github.com/cilium/cilium/pkg/command"
)

var nodeIDListCmd = &cobra.Command{
	Use:     "list",
	Aliases: []string{"ls"},
	Short:   "List node IDs and the associated IP addresses",
	Run: func(cmd *cobra.Command, args []string) {
		listNodeIDs()
	},
}

func init() {
	nodeIDCmd.AddCommand(nodeIDListCmd)
	command.AddOutputOption(nodeIDListCmd)
}

func listNodeIDs() {
	params := daemonApi.NewGetNodeIdsParams().WithTimeout(api.ClientTimeout)
	dump, err := client.Daemon.GetNodeIds(params)
	if err != nil {
		Fatalf("Cannot get node IDs: %s", pkg.Hint(err))
	}
	printNodeIDs(dump.Payload)
}

func printNodeIDs(nodeIDs []*models.NodeID) {
	if command.OutputOption() {
		if err := command.PrintOutput(nodeIDs); err != nil {
			Fatalf("Unable to provide %s output: %s", command.OutputOptionString(), err)
		}
		return
	}

	w := tabwriter.NewWriter(os.Stdout, 5, 0, 3, ' ', 0)
	fmt.Fprintf(w, "NODE ID\tIP ADDRESSES\n")
	for _, nodeID := range nodeIDs {
		printNodeID(w, nodeID)
	}
	w.Flush()
}

func printNodeID(w *tabwriter.Writer, nodeID *models.NodeID) {
	first := true
	for _, ip := range nodeID.Ips {
		if first {
			fmt.Fprintf(w, "%d\t%s\n", *nodeID.ID, ip)
			first = false
		} else {
			fmt.Fprintf(w, "\t%s\n", ip)
		}
	}
}
