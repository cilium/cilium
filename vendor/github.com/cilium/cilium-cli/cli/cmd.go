// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cli

import (
	"context"
	"fmt"
	"os"

	mycmd "github.com/cilium/cilium/pkg/cilium-cli/cmd"
	"github.com/cilium/cilium/pkg/cilium-cli/hooks"
	"github.com/spf13/cobra"

	"github.com/cilium/cilium-cli/defaults"
	"github.com/cilium/cilium-cli/k8s"
)

var (
	ContextName string
	Namespace   string
	K8sClient   *k8s.Client
	// Version is the software version.
	// The following variables are set at compile time via LDFLAGS.
	Version string
)

// SetVersion sets the Version string for the cilium command
func SetVersion(v string) {
	Version = v
}

// NewDefaultCiliumCommand returns a new "cilium" cli cobra command without any additional hooks.
func NewDefaultCiliumCommand() *cobra.Command {
	return NewCiliumCommand(&hooks.NopHooks{})
}

// NewCiliumCommand returns a new "cilium" cli cobra command registering all the additional input hooks.
func NewCiliumCommand(hooks hooks.Hooks) *cobra.Command {
	SetVersion(Version)
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

			c, err := k8s.NewClient(ContextName, "", Namespace)
			if err != nil {
				return fmt.Errorf("unable to create Kubernetes client: %w", err)
			}

			K8sClient = c
			ctx := context.WithValue(context.Background(), defaults.NamespaceKey{}, Namespace)
			ctx = context.WithValue(ctx, defaults.K8sClientKey{}, K8sClient)
			ctx = context.WithValue(ctx, defaults.VersionKey{}, Version)
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

	cmd.PersistentFlags().StringVar(&ContextName, "context", "", "Kubernetes configuration context")
	cmd.PersistentFlags().StringVarP(&Namespace, "namespace", "n", "kube-system", "Namespace Cilium is running in")

	cmd.AddCommand(
		newCmdBgp(),
		newCmdClusterMesh(),
		newCmdConfig(),
		newCmdContext(),
		newCmdEncrypt(),
		newCmdHubble(),
		newCmdStatus(),
		newCmdSysdump(hooks),
		newCmdVersion(),
		newCmdInstallWithHelm(),
		newCmdUninstallWithHelm(),
		newCmdUpgradeWithHelm(),
		mycmd.NewCmdConnectivity(hooks),
	)

	cmd.SetOut(os.Stdout)
	cmd.SetErr(os.Stderr)

	return cmd
}
