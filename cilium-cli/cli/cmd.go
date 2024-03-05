// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cli

import (
	"context"
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/cilium/cilium-cli/connectivity/check"
	"github.com/cilium/cilium-cli/k8s"
	"github.com/cilium/cilium-cli/sysdump"
)

var (
	contextName string
	namespace   string

	k8sClient *k8s.Client
)

// NewDefaultCiliumCommand returns a new "cilium" cli cobra command without any additional hooks.
func NewDefaultCiliumCommand() *cobra.Command {
	return NewCiliumCommand(&NopHooks{})
}

// NewCiliumCommand returns a new "cilium" cli cobra command registering all the additional input hooks.
func NewCiliumCommand(hooks Hooks) *cobra.Command {
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

			c, err := k8s.NewClient(contextName, "", namespace)
			if err != nil {
				return fmt.Errorf("unable to create Kubernetes client: %w", err)
			}

			k8sClient = c
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

	cmd.PersistentFlags().StringVar(&contextName, "context", "", "Kubernetes configuration context")
	cmd.PersistentFlags().StringVarP(&namespace, "namespace", "n", "kube-system", "Namespace Cilium is running in")

	cmd.AddCommand(
		newCmdBgp(),
		newCmdClusterMesh(),
		newCmdConfig(),
		newCmdConnectivity(hooks),
		newCmdContext(),
		newCmdEncrypt(),
		newCmdHubble(),
		newCmdStatus(),
		newCmdSysdump(hooks),
		newCmdVersion(),
		newCmdInstallWithHelm(),
		newCmdUninstallWithHelm(),
		newCmdUpgradeWithHelm(),
	)

	cmd.SetOut(os.Stdout)
	cmd.SetErr(os.Stderr)

	return cmd
}

type (
	SysdumpHooks = sysdump.Hooks
)

type NopHooks struct{}

var _ Hooks = &NopHooks{}

func (*NopHooks) AddSysdumpFlags(*pflag.FlagSet)                                  {}
func (*NopHooks) AddSysdumpTasks(*sysdump.Collector) error                        { return nil }
func (*NopHooks) AddConnectivityTestFlags(*pflag.FlagSet)                         {}
func (*NopHooks) AddConnectivityTests(*check.ConnectivityTest) error              { return nil }
func (*NopHooks) DetectFeatures(context.Context, *check.ConnectivityTest) error   { return nil }
func (*NopHooks) SetupAndValidate(context.Context, *check.ConnectivityTest) error { return nil }
