// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"fmt"
	"io"
	"os"
	"sort"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/cilium/cilium/api/v1/models"
	pkg "github.com/cilium/cilium/pkg/client"
	"github.com/cilium/cilium/pkg/command"
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

		if command.OutputOption() {
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
	command.AddOutputOption(nodeListCmd)
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
