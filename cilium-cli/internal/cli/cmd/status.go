// Copyright 2020 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package cmd

import (
	"context"
	"fmt"

	"github.com/cilium/cilium-cli/status"

	"github.com/spf13/cobra"
)

func newCmdStatus() *cobra.Command {
	var verbose bool
	var ciliumNamespace string

	cmd := &cobra.Command{
		Use:   "status",
		Short: "Display status",
		Long:  ``,
		RunE: func(cmd *cobra.Command, args []string) error {
			collector, err := status.NewK8sStatusCollector(context.Background(), k8sClient, ciliumNamespace)
			if err != nil {
				return err
			}

			s, err := collector.Status(context.Background())
			if err != nil {
				return err
			}

			fmt.Println(s.Format())

			return nil
		},
	}

	cmd.Flags().BoolVar(&verbose, "verbose", false, "Verbose otuput")
	cmd.Flags().StringVarP(&ciliumNamespace, "namespace", "n", "kube-system", "Namespace Cilium is running in")
	cmd.Flags().StringVar(&contextName, "context", "", "Kubernetes configuration context")

	return cmd
}
