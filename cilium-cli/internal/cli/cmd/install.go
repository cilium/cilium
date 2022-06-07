// SPDX-License-Identifier: Apache-2.0
// Copyright 2020-2022 Authors of Cilium

package cmd

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/cilium/cilium-cli/defaults"
	"github.com/cilium/cilium-cli/hubble"
	"github.com/cilium/cilium-cli/install"
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
			params.Namespace = namespace

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

	// It can be deprecated since we have a helm option for it
	cmd.Flags().StringVar(&params.ClusterName, "cluster-name", "", "Name of the cluster")
	cmd.Flags().StringSliceVar(&params.DisableChecks, "disable-check", []string{}, "Disable a particular validation check")
	cmd.Flags().StringVar(&params.Version, "version", defaults.Version, "Cilium version to install")
	cmd.Flags().StringVar(&params.DatapathMode, "datapath-mode", "", "Datapath mode to use")
	// It can be deprecated since we have a helm option for it
	cmd.Flags().StringVar(&params.IPAM, "ipam", "", "IP Address Management (IPAM) mode")
	// It can be deprecated since we have a helm option for it
	cmd.Flags().StringVar(&params.IPv4NativeRoutingCIDR, "ipv4-native-routing-cidr", "", "IPv4 CIDR within which native routing is possible")
	// It can be deprecated since we have a helm option for it
	cmd.Flags().IntVar(&params.ClusterID, "cluster-id", 0, "Unique cluster identifier for multi-cluster")
	cmd.Flags().StringVar(&params.InheritCA, "inherit-ca", "", "Inherit/import CA from another cluster")
	// It can be deprecated since we have a helm option for it
	cmd.Flags().StringVar(&params.KubeProxyReplacement, "kube-proxy-replacement", "disabled", "Enable/disable kube-proxy replacement { disabled | probe | strict }")
	cmd.Flags().BoolVar(&params.Wait, "wait", true, "Wait for status to report success (no errors)")
	cmd.Flags().DurationVar(&params.WaitDuration, "wait-duration", defaults.StatusWaitDuration, "Maximum time to wait for status")
	cmd.Flags().BoolVar(&params.RestartUnmanagedPods, "restart-unmanaged-pods", true, "Restart pods which are not being managed by Cilium")
	cmd.Flags().StringVar(&params.Encryption, "encryption", "disabled", "Enable encryption of all workloads traffic { disabled | ipsec | wireguard }")
	// It can be deprecated since we have a helm option for it
	cmd.Flags().BoolVar(&params.NodeEncryption, "node-encryption", false, "Enable encryption of all node to node traffic")
	// It can be deprecated since we have a helm option for it
	cmd.Flags().StringSliceVar(&params.ConfigOverwrites, "config", []string{}, "Set ConfigMap entries { key=value[,key=value,..] }")
	// It can be deprecated since we have a helm option for it
	cmd.Flags().StringVar(&params.AgentImage, "agent-image", "", "Image path to use for Cilium agent")
	// It can be deprecated since we have a helm option for it
	cmd.Flags().StringVar(&params.OperatorImage, "operator-image", "", "Image path to use for Cilium operator")
	cmd.Flags().DurationVar(&params.CiliumReadyTimeout, "cilium-ready-timeout", 5*time.Minute,
		"Timeout for Cilium to become ready before restarting unmanaged pods")
	cmd.Flags().BoolVar(&params.Rollback, "rollback", true, "Roll back installed resources on failure")

	// It can be deprecated since we have a helm option for it
	cmd.Flags().StringVar(&params.Azure.ResourceGroupName, "azure-resource-group", "", "Azure resource group name the cluster is in (required)")
	cmd.Flags().StringVar(&params.Azure.AKSNodeResourceGroup, "azure-node-resource-group", "", "Azure node resource group name the cluster is in. Bypasses `--azure-resource-group` if provided.")
	cmd.Flags().MarkHidden("azure-node-resource-group") // intended for for development purposes, notably CI usage, cf. azure.go
	cmd.Flags().StringVar(&params.Azure.SubscriptionName, "azure-subscription", "", "Azure subscription name the cluster is in (default `az account show`)")
	// It can be deprecated since we have a helm option for it
	cmd.Flags().StringVar(&params.Azure.SubscriptionID, "azure-subscription-id", "", "Azure subscription ID. Bypasses auto-detection and `--azure-subscription` if provided.")
	cmd.Flags().MarkHidden("azure-subscription-id") // intended for for development purposes, notably CI usage, cf. azure.go
	// It can be deprecated since we have a helm option for it
	cmd.Flags().StringVar(&params.Azure.TenantID, "azure-tenant-id", "", "Tenant ID of Azure Service Principal to use for installing Cilium (will create one if none provided)")
	// It can be deprecated since we have a helm option for it
	cmd.Flags().StringVar(&params.Azure.ClientID, "azure-client-id", "", "Client (application) ID of Azure Service Principal to use for installing Cilium (will create one if none provided)")
	// It can be deprecated since we have a helm option for it
	cmd.Flags().StringVar(&params.Azure.ClientSecret, "azure-client-secret", "", "Client secret of Azure Service Principal to use for installing Cilium (will create one if none provided)")
	cmd.Flags().StringVar(&params.K8sVersion, "k8s-version", "", "Kubernetes server version in case auto-detection fails")

	cmd.Flags().StringVar(&params.HelmChartDirectory, "chart-directory", "", "Helm chart directory")
	cmd.Flags().StringSliceVar(&params.HelmOpts.ValueFiles, "helm-values", []string{}, "Specify helm values in a YAML file or a URL (can specify multiple)")
	cmd.Flags().StringArrayVar(&params.HelmOpts.Values, "helm-set", []string{}, "Set helm values on the command line (can specify multiple or separate values with commas: key1=val1,key2=val2)")
	cmd.Flags().StringArrayVar(&params.HelmOpts.StringValues, "helm-set-string", []string{}, "Set helm STRING values on the command line (can specify multiple or separate values with commas: key1=val1,key2=val2)")
	cmd.Flags().StringArrayVar(&params.HelmOpts.FileValues, "helm-set-file", []string{}, "Set helm values from respective files specified via the command line (can specify multiple or separate values with commas: key1=path1,key2=path2)")
	cmd.Flags().StringVar(&params.HelmGenValuesFile, "helm-auto-gen-values", "", "Write an auto-generated helm values into this file")
	cmd.Flags().StringVar(&params.HelmValuesSecretName, "helm-values-secret-name", defaults.HelmValuesSecretName, "Secret name to store the auto-generated helm values file. The namespace is the same as where Cilium will be installed")
	cmd.Flags().StringVar(&params.ImageSuffix, "image-suffix", "", "Set all generated images with this suffix")
	cmd.Flags().StringVar(&params.ImageTag, "image-tag", "", "Set all images with this tag")
	cmd.Flags().BoolVar(&params.ListVersions, "list-versions", false, "List all the available versions without actually installing")

	for flagName := range install.FlagsToHelmOpts {
		// TODO(aanm) Do not mark the flags has deprecated for now.
		// msg := fmt.Sprintf("use --helm-set=%s<=value> instead", helmOpt)
		// err := cmd.Flags().MarkDeprecated(flagName, msg)
		// if err != nil {
		// 	panic(err)
		// }
		install.FlagValues[flagName] = cmd.Flags().Lookup(flagName).Value
	}
	install.FlagValues["config"] = cmd.Flags().Lookup("config").Value

	return cmd
}

func newCmdUninstall() *cobra.Command {
	var params = install.UninstallParameters{Writer: os.Stdout}

	cmd := &cobra.Command{
		Use:   "uninstall",
		Short: "Uninstall Cilium",
		Long:  ``,
		RunE: func(cmd *cobra.Command, args []string) error {
			params.Namespace = namespace
			ctx := context.Background()

			h, err := hubble.NewK8sHubble(ctx,
				k8sClient, hubble.Parameters{
					Namespace:            params.Namespace,
					HelmValuesSecretName: params.HelmValuesSecretName,
					RedactHelmCertKeys:   params.RedactHelmCertKeys,
					Writer:               params.Writer,
					HelmChartDirectory:   params.HelmChartDirectory,
				})
			if err != nil {
				fmt.Printf("⚠ ️ Failed to initialize Hubble uninstaller: %s", err)
			} else if h.Disable(ctx) != nil {
				fmt.Printf("ℹ️  Failed to disable Hubble. This is expected if Hubble is not enabled: %s", err)
			}
			uninstaller := install.NewK8sUninstaller(k8sClient, params)
			if err := uninstaller.Uninstall(context.Background()); err != nil {
				fatalf("Unable to uninstall Cilium:  %s", err)
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&params.HelmChartDirectory, "chart-directory", "", "Helm chart directory")
	cmd.Flags().StringVar(&params.HelmValuesSecretName, "helm-values-secret-name", defaults.HelmValuesSecretName, "Secret name to store the auto-generated helm values file. The namespace is the same as where Cilium will be installed")
	cmd.Flags().BoolVar(&params.RedactHelmCertKeys, "redact-helm-certificate-keys", true, "Do not print in the terminal any certificate keys generated by helm. (Certificates will always be stored unredacted in the secret defined by 'helm-values-secret-name')")
	cmd.Flags().StringVar(&params.TestNamespace, "test-namespace", defaults.ConnectivityCheckNamespace, "Namespace to uninstall Cilium tests from")
	cmd.Flags().BoolVar(&params.Wait, "wait", false, "Wait for uninstallation to have completed")

	return cmd
}

func newCmdUpgrade() *cobra.Command {
	var params = install.Parameters{Writer: os.Stdout}

	cmd := &cobra.Command{
		Use:   "upgrade",
		Short: "Upgrade Cilium in a Kubernetes cluster",
		Long: fmt.Sprintf(`Upgrade Cilium in a Kubernetes cluster

Examples:
# Upgrade Cilium to the latest patch release:
cilium upgrade

# Upgrade Cilium to a specific version
cilium upgrade --version %s
`, defaults.Version),
		RunE: func(cmd *cobra.Command, args []string) error {
			params.Namespace = namespace

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

	cmd.Flags().StringVar(&params.Version, "version", defaults.Version, "Cilium version to install")
	cmd.Flags().BoolVar(&params.Wait, "wait", true, "Wait for status to report success (no errors)")
	cmd.Flags().DurationVar(&params.WaitDuration, "wait-duration", defaults.StatusWaitDuration, "Maximum time to wait for status")
	cmd.Flags().StringVar(&params.AgentImage, "agent-image", "", "Image path to use for Cilium agent")
	cmd.Flags().StringVar(&params.OperatorImage, "operator-image", "", "Image path to use for Cilium operator")
	cmd.Flags().StringVar(&params.RelayImage, "hubble-relay-image", "", "Image path to use for Hubble Relay")

	return cmd
}
