// SPDX-License-Identifier: Apache-2.0
// Copyright 2020 Authors of Cilium

package cmd

import (
	"context"
	"fmt"
	"time"

	"github.com/cilium/cilium-cli/status"

	"github.com/spf13/cobra"
)

func newCmdStatus() *cobra.Command {
	var params = status.K8sStatusParameters{}

	cmd := &cobra.Command{
		Use:   "status",
		Short: "Display status",
		Long:  ``,
		RunE: func(cmd *cobra.Command, args []string) error {
			collector, err := status.NewK8sStatusCollector(context.Background(), k8sClient, params)
			if err != nil {
				return err
			}

			s, err := collector.Status(context.Background())
			// Report the most recent status even if an error occurred.
			if s != nil {
				fmt.Println(s.Format())
			}
			if err != nil {
				fatalf("Unable to determine status:  %s", err)
			}
			return err
		},
	}
	cmd.Flags().StringVarP(&params.Namespace, "namespace", "n", "kube-system", "Namespace Cilium is running in")
	cmd.Flags().BoolVar(&params.Wait, "wait", false, "Wait for status to report success (no errors and warnings)")
	cmd.Flags().DurationVar(&params.WaitDuration, "wait-duration", 15*time.Minute, "Maximum time to wait for status")
	cmd.Flags().BoolVar(&params.IgnoreWarnings, "ignore-warnings", false, "Ignore warnings when waiting for status to report success")
	cmd.Flags().StringVar(&contextName, "context", "", "Kubernetes configuration context")

	return cmd
}
