// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

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
			if err != nil {
				// Report the most recent status even if an error occurred.
				fmt.Fprint(os.Stderr, s.Format())
				fatalf("Unable to determine status:  %s", err)
			}
			if params.Output == status.OutputJSON {
				jsonStatus, err := json.MarshalIndent(s, "", " ")
				if err != nil {
					// Report the most recent status even if an error occurred.
					fmt.Fprint(os.Stderr, s.Format())
					fatalf("Unable to marshal status to JSON:  %s", err)
				}
				fmt.Println(string(jsonStatus))
			} else {
				fmt.Print(s.Format())
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
	cmd.Flags().StringVarP(&params.Output, "output", "o", status.OutputSummary, "Output format. One of: json, summary")

	return cmd
}
