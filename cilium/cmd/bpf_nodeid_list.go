// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"errors"
	"fmt"
	"io/fs"
	"net"
	"os"
	"text/tabwriter"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/command"
	"github.com/cilium/cilium/pkg/common"
	"github.com/cilium/cilium/pkg/maps/nodemap"

	"github.com/spf13/cobra"
)

const (
	nodeIDListUsage = "List node IDs and their IP addresses.\n"
)

type nodeID struct {
	ID      uint16
	Address string
}

var bpfNodeIDListCmd = &cobra.Command{
	Use:   "list",
	Short: "List node IDs and their IP addresses",
	Long:  nodeIDListUsage,
	Run: func(cmd *cobra.Command, args []string) {
		common.RequireRootPrivilege("cilium bpf nodeid list")

		bpfNodeIDList := []nodeID{}
		parse := func(key *nodemap.NodeKey, val *nodemap.NodeValue) {
			address := key.IP.String()
			if key.Family == bpf.EndpointKeyIPv4 {
				address = net.IP(key.IP[:net.IPv4len]).String()
			}
			bpfNodeIDList = append(bpfNodeIDList, nodeID{
				ID:      val.NodeID,
				Address: address,
			})
		}

		nodeMap, err := nodemap.LoadNodeMap()
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				fmt.Fprintln(os.Stderr, "Cannot find node bpf map")
				return
			}

			Fatalf("Cannot load node bpf map: %s", err)
		}

		if err := nodeMap.IterateWithCallback(parse); err != nil {
			Fatalf("Error dumping contents of the node ID map: %s\n", err)
		}

		if command.OutputOption() {
			if err := command.PrintOutput(bpfNodeIDList); err != nil {
				Fatalf("error getting output of map in JSON: %s\n", err)
			}
			return
		}

		if len(bpfNodeIDList) == 0 {
			fmt.Fprintf(os.Stderr, "No entries found.\n")
		} else {
			printNodeIDList(bpfNodeIDList)
		}
	},
}

func printNodeIDList(nodeIDList []nodeID) {
	w := tabwriter.NewWriter(os.Stdout, 5, 0, 3, ' ', 0)

	fmt.Fprintln(w, "NODE ID\tIP ADDRESSES")
	for _, nodeID := range nodeIDList {
		fmt.Fprintf(w, "%d\t%s\n", nodeID.ID, nodeID.Address)
	}

	w.Flush()
}

func init() {
	bpfNodeIDCmd.AddCommand(bpfNodeIDListCmd)
	command.AddOutputOption(bpfNodeIDListCmd)
}
