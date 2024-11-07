// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package list

import (
	"context"
	"fmt"
	"io"
	"sort"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
	"google.golang.org/grpc"

	observerpb "github.com/cilium/cilium/api/v1/observer"
	relaypb "github.com/cilium/cilium/api/v1/relay"
	"github.com/cilium/cilium/hubble/cmd/common/config"
	"github.com/cilium/cilium/hubble/cmd/common/conn"
	"github.com/cilium/cilium/hubble/cmd/common/template"
	"github.com/cilium/cilium/pkg/time"
)

const notAvailable = "N/A"

func newNodeCommand(vp *viper.Viper) *cobra.Command {
	listCmd := &cobra.Command{
		Use:     "nodes",
		Aliases: []string{"node"},
		Short:   "List Hubble nodes",
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx, cancel := context.WithCancel(cmd.Context())
			defer cancel()
			hubbleConn, err := conn.NewWithFlags(ctx, vp)
			if err != nil {
				return err
			}
			defer hubbleConn.Close()
			return runListNodes(ctx, cmd, hubbleConn)
		},
	}

	// formatting flags
	formattingFlags := pflag.NewFlagSet("Formatting", pflag.ContinueOnError)
	formattingFlags.StringVarP(
		&listOpts.output, "output", "o", "table",
		`Specify the output format, one of:
 json:     JSON encoding
 table:    Tab-aligned columns
 wide:     Tab-aligned columns with additional information`)
	listCmd.Flags().AddFlagSet(formattingFlags)

	// advanced completion for flags
	listCmd.RegisterFlagCompletionFunc("output", func(_ *cobra.Command, _ []string, _ string) ([]string, cobra.ShellCompDirective) {
		return []string{
			"json",
			"table",
			"wide",
		}, cobra.ShellCompDirectiveDefault
	})

	template.RegisterFlagSets(listCmd, formattingFlags, config.ServerFlags)
	return listCmd
}

func runListNodes(ctx context.Context, cmd *cobra.Command, conn *grpc.ClientConn) error {
	req := &observerpb.GetNodesRequest{}
	res, err := observerpb.NewObserverClient(conn).GetNodes(ctx, req)
	if err != nil {
		return err
	}

	nodes := res.GetNodes()
	sort.Slice(nodes, func(i, j int) bool {
		return nodes[i].GetName() < nodes[j].GetName()
	})
	switch listOpts.output {
	case "json":
		return jsonOutput(cmd.OutOrStdout(), nodes)
	case "table", "wide":
		return nodeTableOutput(cmd.OutOrStdout(), nodes)
	default:
		return fmt.Errorf("unknown output format: %s", listOpts.output)
	}
}

func nodeTableOutput(buf io.Writer, nodes []*observerpb.Node) error {
	tw := tabwriter.NewWriter(buf, 2, 0, 3, ' ', 0)
	fmt.Fprint(tw, "NAME\tSTATUS\tAGE\tFLOWS/S\tCURRENT/MAX-FLOWS")
	if listOpts.output == "wide" {
		fmt.Fprint(tw, "\tVERSION\tADDRESS\tTLS")
	}
	fmt.Fprintln(tw)

	for _, n := range nodes {
		age := notAvailable
		flowsPerSec := notAvailable
		if uptime := time.Duration(n.GetUptimeNs()).Round(time.Second); uptime > 0 {
			age = uptime.String()
			flowsPerSec = fmt.Sprintf("%.2f", float64(n.GetSeenFlows())/uptime.Seconds())
		}
		flowsRatio := notAvailable
		if maxFlows := n.GetMaxFlows(); maxFlows > 0 {
			flowsRatio = fmt.Sprintf("%d/%d (%6.2f%%)", n.GetNumFlows(), maxFlows, (float64(n.GetNumFlows())/float64(maxFlows))*100)
		}
		version := notAvailable
		if v := n.GetVersion(); v != "" {
			version = v
		}
		fmt.Fprint(tw, n.GetName(), "\t", strings.Title(nodeStateToString(n.GetState())), "\t", age, "\t", flowsPerSec, "\t", flowsRatio)
		if listOpts.output == "wide" {
			tls := notAvailable
			if t := n.GetTls(); t != nil {
				tls = "Disabled"
				if t.GetEnabled() {
					tls = "Enabled"
				}
			}
			fmt.Fprint(tw, "\t", version, "\t", n.GetAddress(), "\t", tls)
		}
		fmt.Fprintln(tw)
	}
	return tw.Flush()
}

func nodeStateToString(state relaypb.NodeState) string {
	switch state {
	case relaypb.NodeState_NODE_CONNECTED:
		return "connected"
	case relaypb.NodeState_NODE_UNAVAILABLE:
		return "unavailable"
	case relaypb.NodeState_NODE_GONE:
		return "gone"
	case relaypb.NodeState_NODE_ERROR:
		return "error"
	case relaypb.NodeState_UNKNOWN_NODE_STATE:
		fallthrough
	default:
		return "unknown"
	}
}
