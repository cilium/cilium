// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"context"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/cilium/cilium-cli/defaults"
	"github.com/cilium/cilium-cli/status"
)

func newCmdStatus() *cobra.Command {
	var params = status.K8sStatusParameters{}

	cmd := &cobra.Command{
		Use:   "status",
		Short: "Display status",
		Long:  ``,
		RunE: func(cmd *cobra.Command, args []string) error {
			params.Namespace = namespace

			collector, err := status.NewK8sStatusCollector(k8sClient, params)
			if err != nil {
				return err
			}

			s, err := collector.Status(context.Background())
			// Report the most recent status even if an error occurred.
			fmt.Print(s.Format())
			if err != nil {
				fatalf("Unable to determine status:  %s", err)
			}
			return err
		},
	}
	cmd.Flags().BoolVar(&params.Wait, "wait", false, "Wait for status to report success (no errors and warnings)")
	cmd.Flags().DurationVar(&params.WaitDuration, "wait-duration", defaults.StatusWaitDuration, "Maximum time to wait for status")
	cmd.Flags().BoolVar(&params.IgnoreWarnings, "ignore-warnings", false, "Ignore warnings when waiting for status to report success")
	cmd.Flags().IntVar(&params.WorkerCount,
		"worker-count", status.DefaultWorkerCount,
		"The number of workers to use")

	return cmd
}
