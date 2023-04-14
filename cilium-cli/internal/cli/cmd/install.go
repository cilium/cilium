// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"context"
	"fmt"
	"io"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/cilium/cilium-cli/connectivity/check"
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

			cmd.Flags().Visit(func(f *pflag.Flag) {
				if f.Name == "kube-proxy-replacement" {
					params.UserSetKubeProxyReplacement = true
				} else if f.Name == "helm-set" && strings.Contains(f.Value.String(), "kubeProxyReplacement") {
					params.UserSetKubeProxyReplacement = true
				}
			})

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

	addCommonInstallFlags(cmd, &params)
	addCommonHelmFlags(cmd, &params)
	cmd.Flags().StringSliceVar(&params.DisableChecks, "disable-check", []string{}, "Disable a particular validation check")
	// It can be deprecated since we have a helm option for it
	cmd.Flags().StringVar(&params.IPAM, "ipam", "", "IP Address Management (IPAM) mode")
	cmd.Flags().MarkDeprecated("ipam", "IPAM mode is autodetected depending on `datapath-mode`. If needed, this can now be overridden via `helm-set` (Helm value: `ipam.mode`).")
	// It can be deprecated since we have a helm option for it
	cmd.Flags().StringVar(&params.IPv4NativeRoutingCIDR, "ipv4-native-routing-cidr", "", "IPv4 CIDR within which native routing is possible")
	cmd.Flags().MarkDeprecated("ipv4-native-routing-cidr", "This can now be overridden via `helm-set` (Helm value: `ipv4NativeRoutingCIDR`).")
	// It can be deprecated since we have a helm option for it
	cmd.Flags().IntVar(&params.ClusterID, "cluster-id", 0, "Unique cluster identifier for multi-cluster")
	cmd.Flags().MarkDeprecated("cluster-id", "This can now be overridden via `helm-set` (Helm value: `cluster.id`).")
	cmd.Flags().StringVar(&params.InheritCA, "inherit-ca", "", "Inherit/import CA from another cluster")
	// It can be deprecated since we have a helm option for it
	cmd.Flags().StringVar(&params.KubeProxyReplacement, "kube-proxy-replacement", "disabled", "Enable/disable kube-proxy replacement { disabled | partial | strict }")
	cmd.Flags().MarkDeprecated("kube-proxy-replacement", "This can now be overridden via `helm-set` (Helm value: `kubeProxyReplacement`).")
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

	cmd.Flags().StringVar(&params.HelmGenValuesFile, "helm-auto-gen-values", "", "Write an auto-generated helm values into this file")
	cmd.Flags().StringVar(&params.HelmValuesSecretName, "helm-values-secret-name", defaults.HelmValuesSecretName, "Secret name to store the auto-generated helm values file. The namespace is the same as where Cilium will be installed")
	cmd.Flags().StringSliceVar(&params.APIVersions, "api-versions", []string{}, "Kubernetes API versions to use for helm's Capabilities.APIVersions in case discovery fails")
	cmd.Flags().StringVar(&params.ImageSuffix, "image-suffix", "", "Set all generated images with this suffix")
	cmd.Flags().StringVar(&params.ImageTag, "image-tag", "", "Set all images with this tag")

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

			cc, err := check.NewConnectivityTest(k8sClient, check.Parameters{
				CiliumNamespace: namespace,
				TestNamespace:   params.TestNamespace,
				FlowValidation:  check.FlowValidationModeDisabled,
				Writer:          os.Stdout,
			}, Version)
			if err != nil {
				fmt.Printf("⚠ ️ Failed to initialize connectivity test uninstaller: %s", err)
			} else {
				cc.UninstallResources(ctx, params.Wait)
			}

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
			} else if h.Disable(ctx, true) != nil {
				fmt.Printf("ℹ️  Failed to disable Hubble. This is expected if Hubble is not enabled: %s", err)
			}
			uninstaller := install.NewK8sUninstaller(k8sClient, params)
			if err := uninstaller.Uninstall(context.Background()); err != nil {
				fatalf("Unable to uninstall Cilium:  %s", err)
			}
			return nil
		},
	}

	addCommonUninstallFlags(cmd, &params)
	cmd.Flags().StringVar(&params.HelmChartDirectory, "chart-directory", "", "Helm chart directory")
	cmd.Flags().StringVar(&params.HelmValuesSecretName, "helm-values-secret-name", defaults.HelmValuesSecretName, "Secret name to store the auto-generated helm values file. The namespace is the same as where Cilium will be installed")
	cmd.Flags().BoolVar(&params.RedactHelmCertKeys, "redact-helm-certificate-keys", true, "Do not print in the terminal any certificate keys generated by helm. (Certificates will always be stored unredacted in the secret defined by 'helm-values-secret-name')")
	cmd.Flags().IntVar(&params.WorkerCount, "worker-count", runtime.NumCPU(), "Number of workers to use for parallel operations")

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
	cmd.Flags().StringVar(&params.ClusterMeshAPIImage, "clustermesh-apiserver-image", "", "Image path to use for cluster mesh API server")

	return cmd
}

// addCommonInstallFlags adds install command flags that are shared between classic and helm mode.
func addCommonInstallFlags(cmd *cobra.Command, params *install.Parameters) {
	// We can't get rid of --cluster-name until we fix https://github.com/cilium/cilium-cli/issues/1347.
	cmd.Flags().StringVar(&params.ClusterName, "cluster-name", "", "Name of the cluster")
	cmd.Flags().MarkDeprecated("cluster-name", "This can now be overridden via `helm-set` (Helm value: `cluster.name`).")
	cmd.Flags().StringVar(&params.Version, "version", defaults.Version, "Cilium version to install")
	cmd.Flags().StringVar(&params.DatapathMode, "datapath-mode", "", "Datapath mode to use { tunnel | aws-eni | gke | azure | aks-byocni } (default: autodetected).")
	cmd.Flags().BoolVar(&params.ListVersions, "list-versions", false, "List all the available versions without actually installing")
	cmd.Flags().StringSliceVar(&params.NodesWithoutCilium, "nodes-without-cilium", []string{}, "List of node names on which Cilium will not be installed. In Helm installation mode, it's assumed that the no-schedule node labels are present and that the infastructure has set up routing on these nodes to provide connectivity within the Cilium cluster.")
}

// addCommonUninstallFlags adds uninstall command flags that are shared between classic and helm mode.
func addCommonUninstallFlags(cmd *cobra.Command, params *install.UninstallParameters) {
	cmd.Flags().StringVar(&params.TestNamespace, "test-namespace", defaults.ConnectivityCheckNamespace, "Namespace to uninstall Cilium tests from")
	cmd.Flags().BoolVar(&params.Wait, "wait", false, "Wait for uninstallation to have completed")
}

// addCommonHelmFlags adds flags which are used by all subcommands that use Helm underneath.
// These flags are primarily used with a call to helm.MergeVals to allow setting and overriding all helm options via
// flags and values files. These are flags that we will keep in the future for helm-based subcommands, all other similar
// flags are likely to be removed in the future.
func addCommonHelmFlags(cmd *cobra.Command, params *install.Parameters) {
	cmd.Flags().StringVar(&params.HelmChartDirectory, "chart-directory", "", "Helm chart directory")
	cmd.Flags().StringSliceVar(&params.HelmOpts.ValueFiles, "helm-values", []string{}, "Specify helm values in a YAML file or a URL (can specify multiple)")
	cmd.Flags().StringArrayVar(&params.HelmOpts.Values, "helm-set", []string{}, "Set helm values on the command line (can specify multiple or separate values with commas: key1=val1,key2=val2)")
	cmd.Flags().StringArrayVar(&params.HelmOpts.StringValues, "helm-set-string", []string{}, "Set helm STRING values on the command line (can specify multiple or separate values with commas: key1=val1,key2=val2)")
	cmd.Flags().StringArrayVar(&params.HelmOpts.FileValues, "helm-set-file", []string{}, "Set helm values from respective files specified via the command line (can specify multiple or separate values with commas: key1=path1,key2=path2)")
	cmd.Flags().BoolVar(&params.Wait, "wait", false, "Wait for helm install to finish")
	cmd.Flags().DurationVar(&params.WaitDuration, "wait-duration", defaults.StatusWaitDuration, "Maximum time to wait for status")
}

func newCmdInstallWithHelm() *cobra.Command {
	var params = install.Parameters{Writer: os.Stdout}

	cmd := &cobra.Command{
		Use:   "install",
		Short: "Install Cilium in a Kubernetes cluster using Helm",
		Long: `Install Cilium in a Kubernetes cluster using Helm

Examples:
# Install Cilium in current Kubernetes context with default parameters
cilium install

# Install Cilium into Kubernetes context "kind-cluster1" and also set cluster
# name and ID to prepare for multi-cluster capabilities.
cilium install --context kind-cluster1 --helm-set cluster.id=1 --helm-set cluster.name=cluster1
`,
		RunE: func(cmd *cobra.Command, args []string) error {
			params.Namespace = namespace
			// Don't log anything if it's a dry run so that the dry run output can easily be piped to other commands.
			if params.DryRun || params.DryRunHelmValues {
				params.Writer = io.Discard
			}
			installer, err := install.NewK8sInstaller(k8sClient, params)
			if err != nil {
				return err
			}
			cmd.SilenceUsage = true
			if err := installer.InstallWithHelm(context.Background(), k8sClient.RESTClientGetter); err != nil {
				fatalf("Unable to install Cilium: %s", err)
			}
			return nil
		},
	}

	addCommonInstallFlags(cmd, &params)
	addCommonHelmFlags(cmd, &params)
	cmd.Flags().BoolVar(&params.DryRun, "dry-run", false, "Write resources to be installed to stdout without actually installing them")
	cmd.Flags().BoolVar(&params.DryRunHelmValues, "dry-run-helm-values", false, "Write non-default Helm values to stdout without performing the actual installation")
	return cmd
}

func newCmdUninstallWithHelm() *cobra.Command {
	var params = install.UninstallParameters{Writer: os.Stdout}

	cmd := &cobra.Command{
		Use:   "uninstall",
		Short: "Uninstall Cilium using Helm",
		Long:  ``,
		RunE: func(cmd *cobra.Command, args []string) error {
			params.Namespace = namespace
			ctx := context.Background()

			cc, err := check.NewConnectivityTest(k8sClient, check.Parameters{
				CiliumNamespace: namespace,
				TestNamespace:   params.TestNamespace,
				FlowValidation:  check.FlowValidationModeDisabled,
				Writer:          os.Stdout,
			}, Version)
			if err != nil {
				fmt.Printf("⚠ ️ Failed to initialize connectivity test uninstaller: %s", err)
			} else {
				cc.UninstallResources(ctx, params.Wait)
			}
			uninstaller := install.NewK8sUninstaller(k8sClient, params)
			if err := uninstaller.UninstallWithHelm(k8sClient.RESTClientGetter); err != nil {
				fatalf("Unable to uninstall Cilium:  %s", err)
			}
			return nil
		},
	}

	addCommonUninstallFlags(cmd, &params)
	return cmd
}

func newCmdUpgradeWithHelm() *cobra.Command {
	var params = install.Parameters{Writer: os.Stdout}

	cmd := &cobra.Command{
		Use:   "upgrade",
		Short: "Upgrade a Cilium installation a Kubernetes cluster using Helm",
		Long: `Upgrade a Cilium installation in a Kubernetes cluster using Helm

Examples:
# Upgrade Cilium to the latest version, using existing parameters
cilium upgrade

# Upgrade Cilium to the latest version and also set cluster name and ID
# to prepare for multi-cluster capabilities.
cilium upgrade --helm-set cluster.id=1 --helm-set cluster.name=cluster1
`,
		RunE: func(cmd *cobra.Command, args []string) error {
			params.Namespace = namespace
			// Don't log anything if it's a dry run so that the dry run output can easily be piped to other commands.
			if params.DryRun || params.DryRunHelmValues {
				params.Writer = io.Discard
			}
			installer, err := install.NewK8sInstaller(k8sClient, params)
			if err != nil {
				return err
			}
			cmd.SilenceUsage = true
			if err := installer.UpgradeWithHelm(context.Background(), k8sClient.RESTClientGetter); err != nil {
				fatalf("Unable to upgrade Cilium: %s", err)
			}
			return nil
		},
	}

	addCommonInstallFlags(cmd, &params)
	addCommonHelmFlags(cmd, &params)
	cmd.Flags().BoolVar(&params.HelmResetValues, "reset-values", false,
		"When upgrading, reset the helm values to the ones built into the chart")
	cmd.Flags().BoolVar(&params.HelmReuseValues, "reuse-values", true,
		"When upgrading, reuse the helm values from the latest release unless any overrides from are set from other flags. This option takes precedence over HelmResetValues")
	cmd.Flags().BoolVar(&params.DryRun, "dry-run", false,
		"Write resources to be installed to stdout without actually installing them")
	cmd.Flags().BoolVar(&params.DryRunHelmValues, "dry-run-helm-values", false,
		"Write non-default Helm values to stdout; without performing the actual upgrade")
	return cmd
}
