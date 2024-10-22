// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cli

import (
	"context"
	"time"

	"github.com/spf13/cobra"

	"github.com/cilium/cilium/cilium-cli/bgp"
	"github.com/cilium/cilium/cilium-cli/defaults"
	"github.com/cilium/cilium/cilium-cli/status"
)

func newCmdBgp() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "bgp",
		Short: "Access to BGP control plane",
		Long:  ``,
	}

	cmd.AddCommand(newCmdBgpPeers())
	cmd.AddCommand(newCmdBgpRoutes())

	return cmd
}

func newCmdBgpPeers() *cobra.Command {
	params := bgp.Parameters{}

	cmd := &cobra.Command{
		Use:     "peers",
		Aliases: []string{"neighbors"},
		Short:   "Lists BGP peering state",
		Long:    "This command lists the BGP state from all nodes in the cluster - requires cilium >= v1.13.2",
		RunE: func(_ *cobra.Command, _ []string) error {
			params.CiliumNamespace = namespace

			s := bgp.NewStatus(k8sClient, params)
			err := s.GetPeeringState(context.Background())
			if err != nil {
				fatalf("Unable to get peering status: %s", err)
			}

			return nil
		},
	}

	cmd.Flags().StringVar(&params.AgentPodSelector, "agent-pod-selector", defaults.AgentPodSelector, "Label on cilium-agent pods to select with")
	cmd.Flags().StringVar(&params.NodeName, "node", "", "Node from which BGP status will be fetched, omit to select all nodes")
	cmd.Flags().DurationVar(&params.WaitDuration, "wait-duration", 1*time.Minute, "Maximum time to wait for result, default 1 minute")
	cmd.Flags().StringVarP(&params.Output, "output", "o", status.OutputSummary, "Output format. One of: json, summary")

	return cmd
}

func newCmdBgpRoutes() *cobra.Command {
	params := bgp.Parameters{}

	cmd := &cobra.Command{
		Use:   "routes <available | advertised> <afi> <safi> [vrouter <asn>] [peer|neighbor <address>]",
		Short: "Lists BGP routes",
		Long:  "Lists BGP routes from all nodes in the cluster - requires cilium >= v1.14.6",
		Example: `  Get all IPv4 unicast routes available:
    cilium bgp routes available ipv4 unicast

  Get all IPv6 unicast routes available for a specific vrouter:
    cilium bgp routes available ipv6 unicast vrouter 65001

  Get IPv4 unicast routes advertised to a specific peer:
    cilium bgp routes advertised ipv4 unicast peer 10.0.0.1`,

		RunE: func(_ *cobra.Command, args []string) error {
			params.CiliumNamespace = namespace

			s := bgp.NewStatus(k8sClient, params)
			err := s.GetRoutes(context.Background(), args)
			if err != nil {
				fatalf("Unable to get BGP routes: %s", err)
			}

			return nil
		},
	}

	cmd.Flags().StringVar(&params.AgentPodSelector, "agent-pod-selector", defaults.AgentPodSelector, "Label on cilium-agent pods to select with")
	cmd.Flags().StringVar(&params.NodeName, "node", "", "Node from which BGP routes will be fetched, omit to select all nodes")
	cmd.Flags().DurationVar(&params.WaitDuration, "wait-duration", 1*time.Minute, "Maximum time to wait for result, default 1 minute")
	cmd.Flags().StringVarP(&params.Output, "output", "o", status.OutputSummary, "Output format. One of: json, summary")

	return cmd
}
