// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"context"
	"time"

	"github.com/spf13/cobra"

	"github.com/cilium/cilium-cli/bgp"
	"github.com/cilium/cilium-cli/defaults"
	"github.com/cilium/cilium-cli/status"
)

func newCmdBgp() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "bgp",
		Short: "Access to BGP control plane",
		Long:  ``,
	}

	cmd.AddCommand(newCmdBgpPeers())

	return cmd
}

func newCmdBgpPeers() *cobra.Command {
	params := bgp.Parameters{}

	cmd := &cobra.Command{
		Use:   "peers",
		Short: "Lists BGP peering state",
		Long:  "This command lists the BGP state from all nodes in the cluster",
		RunE: func(cmd *cobra.Command, args []string) error {
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
