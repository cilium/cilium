// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"context"
	"time"

	"github.com/spf13/cobra"

	"github.com/cilium/cilium-cli/defaults"
	"github.com/cilium/cilium-cli/encrypt"
	"github.com/cilium/cilium-cli/status"
)

func newCmdEncrypt() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "encryption",
		Short:   "Cilium encryption",
		Long:    ``,
		Aliases: []string{"encrypt"},
	}
	cmd.AddCommand(newCmdEncryptStatus())
	return cmd
}

func newCmdEncryptStatus() *cobra.Command {
	params := encrypt.Parameters{}
	cmd := &cobra.Command{
		Use:   "status",
		Short: "Display encryption status",
		Long:  "This command returns encryption status from all nodes in the cluster",
		RunE: func(cmd *cobra.Command, args []string) error {
			params.CiliumNamespace = namespace
			s := encrypt.NewStatus(k8sClient, params)
			if err := s.GetEncryptStatus(context.Background()); err != nil {
				fatalf("Unable to get encrypt status: %s", err)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&params.AgentPodSelector, "agent-pod-selector", defaults.AgentPodSelector, "Label on cilium-agent pods to select with")
	cmd.Flags().StringVar(&params.NodeName, "node", "", "Node from which encryption status will be fetched, omit to select all nodes")
	cmd.Flags().BoolVar(&params.PerNodeDetails, "per-node-details", false, "Encryption status will be displayed for each cluster node separately")
	cmd.Flags().DurationVar(&params.WaitDuration, "wait-duration", 1*time.Minute, "Maximum time to wait for result, default 1 minute")
	cmd.Flags().StringVarP(&params.Output, "output", "o", status.OutputSummary, "Output format. One of: json, summary")
	return cmd
}
