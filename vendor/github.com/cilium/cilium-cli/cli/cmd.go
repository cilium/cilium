// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cli

import (
	"context"
	"fmt"
	"os"

	mycmd "github.com/cilium/cilium/pkg/cilium-cli/cmd"
	"github.com/cilium/cilium/pkg/cilium-cli/hooks"

	cmd3 "github.com/cilium/cilium-cli/internal/cli/cmd"
	"github.com/cilium/cilium-cli/k8s"
	"github.com/spf13/cobra"
)

// The following variables are set at compile time via LDFLAGS.
var (
	// Version is the software version.
	Version string
)

func NewDefaultCiliumCommand() *cobra.Command {
	return NewCiliumCommand(&hooks.NopHooks{})
}

func NewCiliumCommand(hooks hooks.Hooks) *cobra.Command {
	cmd3.SetVersion(Version)
	cmd := &cobra.Command{
		PersistentPreRunE: func(cmd *cobra.Command, _ []string) error {
			// return early for commands that don't require the kubernetes client
			if !cmd.HasParent() { // this is root
				return nil
			}
			switch cmd.Name() {
			case "completion", "help":
				return nil
			}

			c, err := k8s.NewClient(cmd3.ContextName, "", cmd3.Namespace)
			if err != nil {
				return fmt.Errorf("unable to create Kubernetes client: %w", err)
			}

			cmd3.K8sClient = c
			ctx := context.WithValue(context.Background(), "namespace", cmd3.Namespace)
			ctx = context.WithValue(ctx, "k8sClient", cmd3.K8sClient)
			ctx = context.WithValue(ctx, "version", cmd3.Version)
			cmd.SetContext(ctx)
			return nil
		},
		Run: func(cmd *cobra.Command, _ []string) {
			cmd.Help()
		},
		Use:   "cilium",
		Short: "Cilium provides eBPF-based Networking, Security, and Observability for Kubernetes",
		Long: `CLI to install, manage, & troubleshooting Cilium clusters running Kubernetes.

Cilium is a CNI for Kubernetes to provide secure network connectivity and
load-balancing with excellent visibility using eBPF

Examples:
# Install Cilium in current Kubernetes context
cilium install

# Check status of Cilium
cilium status

# Enable the Hubble observability layer
cilium hubble enable

# Perform a connectivity test
cilium connectivity test`,
		SilenceErrors: true, // this is being handled in main, no need to duplicate error messages
		SilenceUsage:  true, // avoid showing help when usage is correct but an error occurred
	}

	cmd.PersistentFlags().StringVar(&cmd3.ContextName, "context", "", "Kubernetes configuration context")
	cmd.PersistentFlags().StringVarP(&cmd3.Namespace, "namespace", "n", "kube-system", "Namespace Cilium is running in")

	cmd.AddCommand(
		mycmd.NewCmdConnectivity(hooks),
	)

	cmd.SetOut(os.Stdout)
	cmd.SetErr(os.Stderr)

	return cmd
}
