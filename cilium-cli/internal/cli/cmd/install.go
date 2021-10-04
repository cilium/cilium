// SPDX-License-Identifier: Apache-2.0
// Copyright 2020 Authors of Cilium

package cmd

import (
	"context"
	"os"
	"time"

	"github.com/cilium/cilium-cli/defaults"
	"github.com/cilium/cilium-cli/hubble"
	"github.com/cilium/cilium-cli/install"

	"github.com/spf13/cobra"
)

func newCmdInstall() *cobra.Command {
	var params = install.Parameters{Writer: os.Stdout}

	cmd := &cobra.Command{
		Use:   "install",
		Short: "Install Cilium in a Kubernetes cluster",
		Long: `Install Cilium in a Kubernetes cluster

Examples:
# Install Cilium in current Kubernetes context with default parameters
cilium install

# Install Cilium into Kubernetes context "kind-cluster1" and also set cluster
# name and ID to prepare for multi-cluster capabilties.
cilium install --context kind-cluster1 --cluster-id 1 --cluster-name cluster1
`,
		RunE: func(cmd *cobra.Command, args []string) error {
			installer, err := install.NewK8sInstaller(k8sClient, params)
			if err != nil {
				return err
			}
			cmd.SilenceUsage = true
			if err := installer.Install(context.Background()); err != nil {
				installer.RollbackInstallation(context.Background())

				fatalf("Unable to install Cilium: %s", err)
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&params.Namespace, "namespace", "n", "kube-system", "Namespace to install Cilium into")
	cmd.Flags().StringVar(&params.ClusterName, "cluster-name", "", "Name of the cluster")
	cmd.Flags().StringSliceVar(&params.DisableChecks, "disable-check", []string{}, "Disable a particular validation check")
	cmd.Flags().StringVar(&params.Version, "version", defaults.Version, "Cilium version to install")
	cmd.Flags().StringVar(&params.BaseVersion, "base-version", defaults.Version,
		"Specify the base Cilium version for configuration purpose in case the --version flag doesn't indicate the actual Cilium version")
	cmd.Flags().MarkHidden("base-version")
	cmd.Flags().StringVar(&params.DatapathMode, "datapath-mode", "", "Datapath mode to use")
	cmd.Flags().StringVar(&params.IPAM, "ipam", "", "IP Address Management (IPAM) mode")
	cmd.Flags().StringVar(&params.NativeRoutingCIDR, "native-routing-cidr", "", "CIDR within which native routing is possible")
	cmd.Flags().IntVar(&params.ClusterID, "cluster-id", 0, "Unique cluster identifier for multi-cluster")
	cmd.Flags().StringVar(&contextName, "context", "", "Kubernetes configuration context")
	cmd.Flags().StringVar(&params.InheritCA, "inherit-ca", "", "Inherit/import CA from another cluster")
	cmd.Flags().StringVar(&params.KubeProxyReplacement, "kube-proxy-replacement", "disabled", "Enable/disable kube-proxy replacement { disabled | probe | strict }")
	cmd.Flags().BoolVar(&params.Wait, "wait", true, "Wait for status to report success (no errors)")
	cmd.Flags().DurationVar(&params.WaitDuration, "wait-duration", 15*time.Minute, "Maximum time to wait for status")
	cmd.Flags().BoolVar(&params.RestartUnmanagedPods, "restart-unmanaged-pods", true, "Restart pods which are not being managed by Cilium")
	cmd.Flags().StringVar(&params.Encryption, "encryption", "disabled", "Enable encryption of all workloads traffic { disabled | ipsec | wireguard }")
	cmd.Flags().BoolVar(&params.NodeEncryption, "node-encryption", false, "Enable encryption of all node to node traffic")
	cmd.Flags().StringSliceVar(&params.ConfigOverwrites, "config", []string{}, "Set ConfigMap entries (key=value)")
	cmd.Flags().StringVar(&params.AgentImage, "agent-image", "", "Image path to use for Cilium agent")
	cmd.Flags().StringVar(&params.OperatorImage, "operator-image", "", "Image path to use for Cilium operator")
	cmd.Flags().DurationVar(&params.CiliumReadyTimeout, "cilium-ready-timeout", 5*time.Minute,
		"Timeout for Cilium to become ready before restarting unmanaged pods")
	cmd.Flags().BoolVar(&params.Rollback, "rollback", true, "Roll back installed resources on failure")

	cmd.Flags().StringVar(&params.Azure.ResourceGroupName, "azure-resource-group", "", "Azure resource group name the cluster is in (required)")
	cmd.Flags().StringVar(&params.Azure.AKSNodeResourceGroup, "azure-node-resource-group", "", "Azure node resource group name the cluster is in. Bypasses `--azure-resource-group` if provided.")
	cmd.Flags().MarkHidden("azure-node-resource-group") // intended for for development purposes, notably CI usage, cf. azure.go
	cmd.Flags().StringVar(&params.Azure.SubscriptionName, "azure-subscription", "", "Azure subscription name the cluster is in (default `az account show`)")
	cmd.Flags().StringVar(&params.Azure.SubscriptionID, "azure-subscription-id", "", "Azure subscription ID. Bypasses auto-detection and `--azure-subscription` if provided.")
	cmd.Flags().MarkHidden("azure-subscription-id") // intended for for development purposes, notably CI usage, cf. azure.go
	cmd.Flags().StringVar(&params.Azure.TenantID, "azure-tenant-id", "", "Tenant ID of Azure Service Principal to use for installing Cilium (will create one if none provided)")
	cmd.Flags().StringVar(&params.Azure.ClientID, "azure-client-id", "", "Client (application) ID of Azure Service Principal to use for installing Cilium (will create one if none provided)")
	cmd.Flags().StringVar(&params.Azure.ClientSecret, "azure-client-secret", "", "Client secret of Azure Service Principal to use for installing Cilium (will create one if none provided)")

	return cmd
}

func newCmdUninstall() *cobra.Command {
	var params = install.UninstallParameters{Writer: os.Stdout}

	cmd := &cobra.Command{
		Use:   "uninstall",
		Short: "Uninstall Cilium",
		Long:  ``,
		RunE: func(cmd *cobra.Command, args []string) error {
			h := hubble.NewK8sHubble(k8sClient, hubble.Parameters{
				Namespace: params.Namespace,
				Writer:    params.Writer,
			})
			h.Disable(context.Background())
			uninstaller := install.NewK8sUninstaller(k8sClient, params)
			if err := uninstaller.Uninstall(context.Background()); err != nil {
				fatalf("Unable to uninstall Cilium:  %s", err)
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&params.Namespace, "namespace", "n", "kube-system", "Namespace to uninstall Cilium from")
	cmd.Flags().StringVar(&params.TestNamespace, "test-namespace", defaults.ConnectivityCheckNamespace, "Namespace to uninstall Cilium tests from")
	cmd.Flags().StringVar(&contextName, "context", "", "Kubernetes configuration context")
	cmd.Flags().BoolVar(&params.Wait, "wait", false, "Wait for uninstallation to have completed")

	return cmd
}

func newCmdUpgrade() *cobra.Command {
	var params = install.Parameters{Writer: os.Stdout}

	cmd := &cobra.Command{
		Use:   "upgrade",
		Short: "Upgrade Cilium in a Kubernetes cluster",
		Long: `Upgrade Cilium in a Kubernetes cluster

Examples:
# Upgrade Cilium to the latest patch release:
cilium upgrade

# Upgrade Cilium to a specific version
cilium upgrade --version v1.10.4
`,
		RunE: func(cmd *cobra.Command, args []string) error {
			installer, err := install.NewK8sInstaller(k8sClient, params)
			if err != nil {
				return err
			}
			cmd.SilenceUsage = true
			if err := installer.Upgrade(context.Background()); err != nil {
				fatalf("Unable to upgrade Cilium:  %s", err)
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&params.Namespace, "namespace", "n", "kube-system", "Namespace to install Cilium into")
	cmd.Flags().StringVar(&params.Version, "version", defaults.Version, "Cilium version to install")
	cmd.Flags().StringVar(&contextName, "context", "", "Kubernetes configuration context")
	cmd.Flags().BoolVar(&params.Wait, "wait", true, "Wait for status to report success (no errors)")
	cmd.Flags().DurationVar(&params.WaitDuration, "wait-duration", 15*time.Minute, "Maximum time to wait for status")
	cmd.Flags().StringVar(&params.AgentImage, "agent-image", "", "Image path to use for Cilium agent")
	cmd.Flags().StringVar(&params.OperatorImage, "operator-image", "", "Image path to use for Cilium operator")

	return cmd
}
