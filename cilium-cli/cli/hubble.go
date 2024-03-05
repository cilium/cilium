// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cli

import (
	"context"
	"os"

	"github.com/cilium/cilium-cli/hubble"

	"github.com/spf13/cobra"
)

func newCmdHubble() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "hubble",
		Short: "Hubble observability",
		Long:  ``,
	}

	cmd.AddCommand(
		newCmdPortForwardCommand(),
		newCmdUI(),
		newCmdHubbleEnableWithHelm(),
		newCmdHubbleDisableWithHelm(),
	)
	return cmd
}

func newCmdPortForwardCommand() *cobra.Command {
	var params = hubble.Parameters{
		Writer: os.Stdout,
	}

	cmd := &cobra.Command{
		Use:   "port-forward",
		Short: "Forward the relay port to the local machine",
		Long:  ``,
		RunE: func(_ *cobra.Command, _ []string) error {
			params.Context = contextName
			params.Namespace = namespace
			ctx := context.Background()

			if err := params.RelayPortForwardCommand(ctx, k8sClient); err != nil {
				fatalf("Unable to port forward: %s", err)
			}
			return nil
		},
	}

	cmd.Flags().IntVar(&params.PortForward, "port-forward", 4245, "Local port to forward to")

	return cmd
}

func newCmdUI() *cobra.Command {
	var params = hubble.Parameters{
		Writer: os.Stdout,
	}

	cmd := &cobra.Command{
		Use:   "ui",
		Short: "Open the Hubble UI",
		RunE: func(_ *cobra.Command, _ []string) error {
			params.Context = contextName
			params.Namespace = namespace

			if err := params.UIPortForwardCommand(); err != nil {
				fatalf("Unable to port forward: %s", err)
			}
			return nil
		},
	}

	cmd.Flags().IntVar(&params.UIPortForward, "port-forward", 12000, "Local port to use for the port forward")
	cmd.Flags().BoolVar(&params.UIOpenBrowser, "open-browser", true, "When --open-browser=false is supplied, cilium Hubble UI will not open the browser")

	return cmd
}

// addCommonUninstallFlags adds uninstall command flags that are shared between classic and helm mode.
func addCommonHubbleEnableFlags(cmd *cobra.Command, params *hubble.Parameters) {
	cmd.Flags().BoolVar(&params.Relay, "relay", true, "Deploy Hubble Relay")
	cmd.Flags().BoolVar(&params.UI, "ui", false, "Enable Hubble UI")
}

func newCmdHubbleEnableWithHelm() *cobra.Command {
	var params = hubble.Parameters{
		Writer: os.Stdout,
	}

	cmd := &cobra.Command{
		Use:   "enable",
		Short: "Enable Hubble observability using Helm",
		Long:  ``,
		RunE: func(_ *cobra.Command, _ []string) error {
			params.Namespace = namespace
			ctx := context.Background()
			if err := hubble.EnableWithHelm(ctx, k8sClient, params); err != nil {
				fatalf("Unable to enable Hubble: %s", err)
			}
			return nil
		},
	}

	addCommonHubbleEnableFlags(cmd, &params)
	return cmd
}

func newCmdHubbleDisableWithHelm() *cobra.Command {
	var params = hubble.Parameters{
		Writer: os.Stdout,
	}

	cmd := &cobra.Command{
		Use:   "disable",
		Short: "Disable Hubble observability using Helm",
		Long:  ``,
		RunE: func(_ *cobra.Command, _ []string) error {
			params.Namespace = namespace
			ctx := context.Background()
			if err := hubble.DisableWithHelm(ctx, k8sClient, params); err != nil {
				fatalf("Unable to disable Hubble:  %s", err)
			}
			return nil
		},
	}

	return cmd
}
