// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cli

import (
	"context"
	"fmt"
	"time"

	"github.com/spf13/cobra"

	"github.com/cilium/cilium/cilium-cli/defaults"
	"github.com/cilium/cilium/cilium-cli/features"
)

func newCmdFeatures() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "features",
		Short:   "Report which features are enabled in Cilium agents",
		Long:    ``,
		Aliases: []string{"fs"},
	}
	cmd.AddCommand(newCmdFeaturesStatus())
	cmd.AddCommand(newCmdFeaturesGH())
	return cmd
}

func newCmdFeaturesGH() *cobra.Command {
	params := features.Parameters{}
	cmd := &cobra.Command{
		Use:   "summary",
		Short: "Stores and generates the summary for the features tested on a CI run",
		Long: "This command will connect to GitHub to retrieve the metrics generated\n" +
			"on a CI run and will generate a summary with the report.\n" +
			"Requires a GitHub Token in GITHUB_TOKEN env variable with permissions to access contents. Direct Link:\n" +
			"https://github.com/settings/tokens/new?description=CI%20Summary%20Generator&scopes=public_repo",
		RunE: func(_ *cobra.Command, _ []string) error {
			s := features.NewFeatures(nil, params)
			if params.Commit == "" {
				return fmt.Errorf("commit flag is not set")
			}
			if err := s.GenSummary(context.Background()); err != nil {
				fatalf("Unable to generate summary features status: %s", err)
			}
			return nil
		},
	}
	cmd.Flags().StringVarP(&params.MetricsDirectory, "metrics-directory", "", "ci-features-metrics", "Directory where the metrics are saved from GitHub.")
	cmd.Flags().StringVarP(&params.Repo, "repo", "r", "cilium/cilium", "Repository to retrieve the metrics from CI.")
	cmd.Flags().StringVarP(&params.Commit, "commit", "c", "", "Commit SHA to retrieve the metrics.")
	cmd.Flags().BoolVarP(&params.GHStepSummaryAnchor, "anchor", "a", false, "Add workaround HTML anchor to generated markdown (For GitHub step summary).")
	cmd.Flags().StringVarP(&params.Output, "output", "o", "markdown", "Output format. One of: markdown")
	cmd.Flags().StringVarP(&params.Outputfile, "output-file", "", "-", "Outputs into a file. Defaults to stdout")
	return cmd
}

func newCmdFeaturesStatus() *cobra.Command {
	params := features.Parameters{}
	cmd := &cobra.Command{
		Use:   "status",
		Short: "Display features status",
		Long:  "This command returns features enabled from all nodes in the cluster",
		RunE: func(_ *cobra.Command, _ []string) error {
			params.CiliumNamespace = namespace
			params.CiliumOperatorNamespace = namespace
			s := features.NewFeatures(k8sClient, params)
			if err := s.PrintFeatureStatus(context.Background()); err != nil {
				fatalf("Unable to print features status: %s", err)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&params.AgentPodSelector, "agent-pod-selector", defaults.AgentPodSelector, "Label on cilium-agent pods to select with")
	cmd.Flags().StringVar(&params.OperatorPodSelector, "operator-pod-selector", defaults.OperatorPodSelector, "Label on cilium-operator pods to select with")
	cmd.Flags().StringVar(&params.CiliumOperatorCommand, "operator-container-command", "", "Binary used to run Cilium Operator")
	cmd.Flags().StringVar(&params.NodeName, "node", "", "Node from which features status will be fetched, omit to select all nodes")
	cmd.Flags().StringVar(&params.OperatorNodeName, "operator-node", "", "Node from which features status will be fetched, omit to select all nodes")
	cmd.Flags().DurationVar(&params.WaitDuration, "wait-duration", 1*time.Minute, "Maximum time to wait for result, default 1 minute")
	cmd.Flags().StringVarP(&params.Output, "output", "o", "tab", "Output format. One of: tab, markdown, json")
	cmd.Flags().StringVarP(&params.Outputfile, "output-file", "", "-", "Outputs into a file. Defaults to stdout")
	return cmd
}
