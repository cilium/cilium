// SPDX-License-Identifier: Apache-2.0
// Copyright 2020-2021 Authors of Cilium

package cmd

import (
	"context"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/cilium/cilium-cli/config"
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
			params.Namespace = namespace

			check := config.NewK8sConfig(k8sClient, params)
			out, err := check.View(context.Background())
			if err != nil {
				fatalf("Unable to view config:  %s", err)
			}
			fmt.Print(out)
			return nil
		},
	}

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
			params.Namespace = namespace

			check := config.NewK8sConfig(k8sClient, params)
			if err := check.Set(context.Background(), args[0], args[1], params); err != nil {
				fatalf("Unable to set config:  %s", err)
			}
			return nil
		},
	}

	cmd.Flags().BoolVarP(&params.Restart, "restart", "r", true, "Restart Cilium pods")
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
			params.Namespace = namespace

			check := config.NewK8sConfig(k8sClient, params)
			if err := check.Delete(context.Background(), args[0], params); err != nil {
				fatalf("Unable to delete config:  %s", err)
			}
			return nil
		},
	}

	cmd.Flags().BoolVarP(&params.Restart, "restart", "r", true, "Restart Cilium pods")

	return cmd
}
