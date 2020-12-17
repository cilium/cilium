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
	"net"

	"github.com/cilium/cilium/api/v1/client/daemon"
	"github.com/cilium/cilium/api/v1/models"

	"github.com/spf13/cobra"
)

var nodeNeighInsertCmd = &cobra.Command{
	Use:     "insert <neigh name> <neigh IP>",
	Short:   "Insert node as a neighbor into current node's neighbor table",
	Example: `cilium node neigh insert "node1" 192.0.2.1`,
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) != 2 {
			Usagef(cmd, "Missing node name and/or node IP")
		}

		if len(args[0]) == 0 {
			Fatalf("Invalid node name, cannot be empty\n")
		}

		if ip := net.ParseIP(args[1]); ip == nil {
			Fatalf("Invalid IP address %q\n", args[1])
		}

		if _, err := client.Daemon.PutClusterNodesNeigh(
			daemon.NewPutClusterNodesNeighParams().WithRequest(&models.NodeNeighRequest{
				Name: args[0],
				IP:   args[1],
			}),
		); err != nil {
			Fatalf("Cannot insert node into neighbor table: %v\n", err)
		}
	},
}

func init() {
	nodeNeighCmd.AddCommand(nodeNeighInsertCmd)
}
