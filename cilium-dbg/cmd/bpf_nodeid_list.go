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

	"github.com/spf13/cobra"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/command"
	"github.com/cilium/cilium/pkg/common"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/maps/nodemap"
)

const (
	nodeIDListUsage = "List node IDs and their IP addresses.\n"
)

type nodeID struct {
	ID      uint16
	Address string
	SPI     uint8
}

var bpfNodeIDListCmd = &cobra.Command{
	Use:   "list",
	Short: "List node IDs and their IP addresses",
	Long:  nodeIDListUsage,
	Run: func(cmd *cobra.Command, args []string) {
		common.RequireRootPrivilege("cilium bpf nodeid list")

		bpfNodeValueList := []nodeID{}
		parse := func(key *nodemap.NodeKey, val *nodemap.NodeValueV2) {
			address := key.IP.String()
			if key.Family == bpf.EndpointKeyIPv4 {
				address = net.IP(key.IP[:net.IPv4len]).String()
			}
			bpfNodeValueList = append(bpfNodeValueList, nodeID{
				ID:      val.NodeID,
				Address: address,
				SPI:     val.SPI,
			})
		}

		nodeMap, err := nodemap.LoadNodeMapV2(logging.DefaultSlogLogger)
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
			if err := command.PrintOutput(bpfNodeValueList); err != nil {
				Fatalf("error getting output of map in JSON: %s\n", err)
			}
			return
		}

		if len(bpfNodeValueList) == 0 {
			fmt.Fprintf(os.Stderr, "No entries found.\n")
		} else {
			printNodeIDList(bpfNodeValueList)
		}
	},
}

func printNodeIDList(nodeValueList []nodeID) {
	w := tabwriter.NewWriter(os.Stdout, 5, 0, 3, ' ', 0)

	fmt.Fprintln(w, "NODE ID\tIP ADDRESSES\tSPI")
	for _, nodeValue := range nodeValueList {
		fmt.Fprintf(w, "0x%x\t%s\t%d\n", nodeValue.ID, nodeValue.Address, nodeValue.SPI)
	}

	w.Flush()
}

func init() {
	BPFNodeIDCmd.AddCommand(bpfNodeIDListCmd)
	command.AddOutputOption(bpfNodeIDListCmd)
}
