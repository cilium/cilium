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
	legacyCMD := &cobra.Command{
		Use:   "legacy",
		Short: "Access to deprecated REST API based BGP commands",
		Long:  ``,
	}

	cmd.AddCommand(legacyCMD, newCmdBgpPeers(), newCmdBgpRoutes())
	legacyCMD.AddCommand(newCmdBgpPeersLegacy(), newCmdBgpRoutesLegacy())

	return cmd
}

func newCmdBgpPeers() *cobra.Command {
	params := bgp.Parameters{}

	cmd := &cobra.Command{
		Use:   "peers",
		Short: "List BGP peers on Cilium",
		Long:  "List current state of all BGP peers configured in Cilium BGP Control Plane",
		RunE: func(_ *cobra.Command, _ []string) error {
			params.CiliumNamespace = RootParams.Namespace

			s := bgp.NewStatus(RootK8sClient, params)
			err := s.GetPeeringState(context.Background())
			if err != nil {
				fatalf("Unable to get peering status: %s", err)
			}

			return nil
		},
	}

	addCommonFlags(cmd, &params)
	cmd.Flags().StringVarP(&params.Output, "format", "f", status.FormatTable, "Format to write in (table or detailed)")

	return cmd
}

func newCmdBgpPeersLegacy() *cobra.Command {
	params := bgp.Parameters{}

	cmd := &cobra.Command{
		Use:     "peers",
		Aliases: []string{"neighbors"},
		Short:   "Lists BGP peering state",
		Long:    "This command lists the BGP state from all nodes in the cluster",
		RunE: func(_ *cobra.Command, _ []string) error {
			params.CiliumNamespace = RootParams.Namespace

			s := bgp.NewStatus(RootK8sClient, params)
			err := s.GetPeeringStateLegacy(context.Background())
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
	cmd.Flags().BoolVarP(&params.ShowCaps, "capabilities", "c", false, "Show all BGP peer capabilities in detail")
	return cmd
}

func newCmdBgpRoutes() *cobra.Command {
	params := bgp.Parameters{}

	cmd := &cobra.Command{
		Use:   "routes <table type> <afi> <safi>",
		Short: "List BGP routes on Cilium",
		Long:  "List routes in the BGP Control Plane's RIBs",
		Example: `  table type: "loc" (loc-rib), "in" (adj-rib-in), or "out" (adj-rib-out).
  afi: Address Family Identifier (e.g. ipv4, ipv6).
  safi: Subsequent Address Family Identifier (e.g. unicast).`,

		RunE: func(_ *cobra.Command, args []string) error {
			params.CiliumNamespace = RootParams.Namespace

			s := bgp.NewStatus(RootK8sClient, params)
			err := s.GetRoutes(context.Background(), args)
			if err != nil {
				fatalf("Unable to get BGP routes: %s", err)
			}

			return nil
		},
	}

	addCommonFlags(cmd, &params)
	cmd.Flags().BoolVarP(&params.ShowAttrs, "with-attrs", "a", false, "Show path attributes (excluding NEXT_HOP and MP_REACH_NLRI)")

	return cmd
}

func newCmdBgpRoutesLegacy() *cobra.Command {
	params := bgp.Parameters{}

	cmd := &cobra.Command{
		Use:   "routes <available | advertised> <afi> <safi> [vrouter <asn>] [peer|neighbor <address>]",
		Short: "Lists BGP routes",
		Long:  "Lists BGP routes from all nodes in the cluster",
		Example: `  Get all IPv4 unicast routes available:
    cilium bgp legacy routes available ipv4 unicast

  Get all IPv6 unicast routes available for a specific vrouter:
    cilium bgp legacy routes available ipv6 unicast vrouter 65001

  Get IPv4 unicast routes advertised to a specific peer:
    cilium bgp legacy routes advertised ipv4 unicast peer 10.0.0.1`,

		RunE: func(_ *cobra.Command, args []string) error {
			params.CiliumNamespace = RootParams.Namespace

			s := bgp.NewStatus(RootK8sClient, params)
			err := s.GetRoutesLegacy(context.Background(), args)
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

func addCommonFlags(cmd *cobra.Command, params *bgp.Parameters) {
	cmd.Flags().StringVar(&params.AgentPodSelector, "agent-pod-selector", defaults.AgentPodSelector, "Label on cilium-agent pods to select with")
	cmd.Flags().StringVar(&params.NodeName, "node", "", "Node from which BGP status will be fetched, omit to select all nodes")
	cmd.Flags().DurationVar(&params.WaitDuration, "wait-duration", 1*time.Minute, "Maximum time to wait for result, default 1 minute")
}
