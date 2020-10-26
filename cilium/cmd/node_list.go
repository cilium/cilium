// Copyright 2018-2019 Authors of Cilium
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
	"io"
	"os"
	"sort"
	"text/tabwriter"

	"github.com/cilium/cilium/api/v1/models"
	pkg "github.com/cilium/cilium/pkg/client"
	"github.com/cilium/cilium/pkg/command"

	"github.com/spf13/cobra"
)

var nodeListCmd = &cobra.Command{
	Use:     "list",
	Aliases: []string{"ls"},
	Short:   "List nodes",
	Run: func(cmd *cobra.Command, args []string) {
		resp, err := client.Daemon.GetClusterNodes(nil)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s\n", pkg.Hint(err))
			os.Exit(1)
		}

		cluster := resp.Payload.NodesAdded
		if cluster == nil {
			return
		}

		if command.OutputJSON() {
			if err := command.PrintOutput(cluster); err != nil {
				os.Exit(1)
			}
			return
		}

		w := tabwriter.NewWriter(os.Stdout, 2, 0, 3, ' ', 0)
		formatStatusResponse(w, cluster)
		w.Flush()
	},
}

func init() {
	nodeCmd.AddCommand(nodeListCmd)
	command.AddJSONOutput(nodeListCmd)
}

func formatStatusResponse(w io.Writer, nodes []*models.NodeElement) {
	nodesOutputHeader := "Name\tIPv4 Address\tEndpoint CIDR\tIPv6 Address\tEndpoint CIDR\n"
	nodesOutput := make([]string, len(nodes))

	for _, node := range nodes {
		ipv4, ipv4Range, ipv6, ipv6Range := "", "", "", ""
		if node.PrimaryAddress != nil {
			if node.PrimaryAddress.IPV4 != nil {
				ipv4 = node.PrimaryAddress.IPV4.IP
				ipv4Range = node.PrimaryAddress.IPV4.AllocRange
			}
			if node.PrimaryAddress.IPV6 != nil {
				ipv6 = node.PrimaryAddress.IPV6.IP
				ipv6Range = node.PrimaryAddress.IPV6.AllocRange
			}
		}

		nodesOutput = append(nodesOutput, fmt.Sprintf("%s\t%s\t%s\t%s\t%s\n",
			node.Name, ipv4, ipv4Range, ipv6, ipv6Range))
	}

	if len(nodesOutput) > 1 {
		tab := tabwriter.NewWriter(w, 0, 0, 3, ' ', 0)
		fmt.Fprint(tab, nodesOutputHeader)
		sort.Strings(nodesOutput)
		for _, s := range nodesOutput {
			fmt.Fprint(tab, s)
		}
		tab.Flush()
	}
}
