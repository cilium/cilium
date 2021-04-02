// Copyright 2020-2021 Authors of Cilium
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
	"os"

	"github.com/cilium/cilium-cli/config"

	"github.com/spf13/cobra"
)

func newCmdConfig() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "config",
		Short: "Manage Configuration",
		Long:  ``,
	}

	cmd.AddCommand(
		newCmdConfigView(),
		newCmdConfigSet(),
		newCmdConfigDelete(),
	)

	return cmd
}

func newCmdConfigView() *cobra.Command {
	var params = config.Parameters{
		Writer: os.Stdout,
	}

	cmd := &cobra.Command{
		Use:   "view",
		Short: "View current configuration",
		Long:  ``,
		RunE: func(cmd *cobra.Command, args []string) error {
			check := config.NewK8sConfig(k8sClient, params)
			out, err := check.View(context.Background())
			if err != nil {
				fatalf("Unable to view config:  %s", err)
			}
			fmt.Print(out)
			return nil
		},
	}

	cmd.Flags().StringVarP(&params.Namespace, "namespace", "n", "kube-system", "Namespace Cilium is running in")

	return cmd
}

func newCmdConfigSet() *cobra.Command {
	var params = config.Parameters{
		Writer: os.Stdout,
	}

	cmd := &cobra.Command{
		Use:   "set",
		Short: "Set a key/value pair in the configuration",
		Long:  ``,
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			check := config.NewK8sConfig(k8sClient, params)
			if err := check.Set(context.Background(), args[0], args[1]); err != nil {
				fatalf("Unable to set config:  %s", err)
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(
		&params.Namespace,
		"namespace",
		"n",
		"kube-system",
		"Namespace Cilium is running in",
	)

	return cmd
}

func newCmdConfigDelete() *cobra.Command {
	var params = config.Parameters{
		Writer: os.Stdout,
	}

	cmd := &cobra.Command{
		Use:   "delete",
		Short: "Delete a key in the configuration",
		Long:  ``,
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			check := config.NewK8sConfig(k8sClient, params)
			if err := check.Delete(context.Background(), args[0]); err != nil {
				fatalf("Unable to delete config:  %s", err)
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(
		&params.Namespace,
		"namespace",
		"n",
		"kube-system",
		"Namespace Cilium is running in",
	)

	return cmd
}
