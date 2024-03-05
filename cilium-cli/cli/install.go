// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cli

import (
	"context"
	"fmt"
	"io"
	"os"

	"github.com/cilium/cilium/pkg/inctimer"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	k8sErrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/cilium/cilium-cli/connectivity/check"
	"github.com/cilium/cilium-cli/defaults"
	"github.com/cilium/cilium-cli/hubble"
	"github.com/cilium/cilium-cli/install"
)

// addCommonInstallFlags adds install command flags that are shared between classic and helm mode.
func addCommonInstallFlags(cmd *cobra.Command, params *install.Parameters) {
	cmd.Flags().StringVar(&params.Version, "version", defaults.Version, "Cilium version to install")
	cmd.Flags().StringVar(&params.DatapathMode, "datapath-mode", "", "Datapath mode to use { tunnel | native | aws-eni | gke | azure | aks-byocni } (default: autodetected).")
	cmd.Flags().BoolVar(&params.ListVersions, "list-versions", false, "List all the available versions without actually installing")
	cmd.Flags().StringSliceVar(&params.NodesWithoutCilium, "nodes-without-cilium", []string{}, "List of node names on which Cilium will not be installed. In Helm installation mode, it's assumed that the no-schedule node labels are present and that the infrastructure has set up routing on these nodes to provide connectivity within the Cilium cluster.")
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
	cmd.Flags().StringSliceVarP(&params.HelmOpts.ValueFiles, "helm-values", "f", []string{}, "Specify helm values in a YAML file or a URL (can specify multiple)")
	cmd.Flags().StringArrayVar(&params.HelmOpts.Values, "helm-set", []string{}, "Set helm values on the command line (can specify multiple or separate values with commas: key1=val1,key2=val2)")
	cmd.Flags().StringArrayVar(&params.HelmOpts.StringValues, "helm-set-string", []string{}, "Set helm STRING values on the command line (can specify multiple or separate values with commas: key1=val1,key2=val2)")
	cmd.Flags().StringArrayVar(&params.HelmOpts.FileValues, "helm-set-file", []string{}, "Set helm values from respective files specified via the command line (can specify multiple or separate values with commas: key1=path1,key2=path2)")
	cmd.Flags().BoolVar(&params.Wait, "wait", false, "Wait for helm install to finish")
	cmd.Flags().DurationVar(&params.WaitDuration, "wait-duration", defaults.StatusWaitDuration, "Maximum time to wait for status")
	cmd.Flags().SetNormalizeFunc(normalizeFlags)
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
cilium install --context kind-cluster1 --set cluster.id=1 --set cluster.name=cluster1
`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			params.Namespace = namespace
			// Don't log anything if it's a dry run so that the dry run output can easily be piped to other commands.
			if params.IsDryRun() {
				params.Writer = io.Discard
			}
			installer, err := install.NewK8sInstaller(k8sClient, params)
			if err != nil {
				return err
			}
			cmd.SilenceUsage = true
			if err := installer.InstallWithHelm(context.Background(), k8sClient); err != nil {
				fatalf("Unable to install Cilium: %s", err)
			}
			return nil
		},
	}

	addCommonInstallFlags(cmd, &params)
	addCommonHelmFlags(cmd, &params)
	cmd.Flags().BoolVar(&params.DryRun, "dry-run", false, "Write resources to be installed to stdout without actually installing them")
	cmd.Flags().BoolVar(&params.DryRunHelmValues, "dry-run-helm-values", false, "Write non-default Helm values to stdout without performing the actual installation")
	cmd.Flags().StringVar(&params.HelmRepository, "repository", defaults.HelmRepository, "Helm chart repository to download Cilium charts from")
	return cmd
}

func newCmdUninstallWithHelm() *cobra.Command {
	var params = install.UninstallParameters{Writer: os.Stdout}

	cmd := &cobra.Command{
		Use:   "uninstall",
		Short: "Uninstall Cilium using Helm",
		Long:  ``,
		RunE: func(_ *cobra.Command, _ []string) error {
			params.Namespace = namespace
			ctx := context.Background()

			cc, err := check.NewConnectivityTest(k8sClient, check.Parameters{
				CiliumNamespace: namespace,
				TestNamespace:   params.TestNamespace,
				FlowValidation:  check.FlowValidationModeDisabled,
				Writer:          os.Stdout,
			}, defaults.CLIVersion)
			if err != nil {
				fmt.Printf("⚠ ️ Failed to initialize connectivity test uninstaller: %s\n", err)
			} else {
				cc.UninstallResources(ctx, params.Wait)
			}
			uninstaller := install.NewK8sUninstaller(k8sClient, params)
			var hubbleParams = hubble.Parameters{
				Writer: os.Stdout,
				Wait:   true,
			}

			if params.Wait {
				// Disable Hubble, then wait for Pods to terminate before uninstalling Cilium.
				// This guarantees that relay Pods are terminated fully via Cilium (rather than
				// being queued for deletion) before uninstalling Cilium.
				fmt.Printf("⌛ Waiting to disable Hubble before uninstalling Cilium\n")
				if err := hubble.DisableWithHelm(ctx, k8sClient, hubbleParams); err != nil {
					fmt.Printf("⚠ ️ Failed to disable Hubble prior to uninstalling Cilium: %s\n", err)
				}
				for {
					ps, err := k8sClient.ListPods(ctx, hubbleParams.Namespace, metav1.ListOptions{
						LabelSelector: "k8s-app=hubble-relay",
					})
					if err != nil {
						if k8sErrors.IsNotFound(err) {
							break
						}
						fatalf("Unable to list pods waiting for hubble-relay to stop: %s", err)
					}
					if len(ps.Items) == 0 {
						break
					}
					select {
					case <-inctimer.After(defaults.WaitRetryInterval):
					case <-ctx.Done():
						fatalf("Timed out waiting for Hubble Pods to terminate")
					}
				}
			}

			fmt.Printf("⌛ Uninstalling Cilium\n")
			if err := uninstaller.UninstallWithHelm(ctx, k8sClient.HelmActionConfig); err != nil {
				fatalf("Unable to uninstall Cilium:  %s", err)
			}
			return nil
		},
	}

	addCommonUninstallFlags(cmd, &params)
	cmd.Flags().DurationVar(&params.Timeout, "timeout", defaults.UninstallTimeout, "Maximum time to wait for resources to be deleted")

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
cilium upgrade --set cluster.id=1 --set cluster.name=cluster1
`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			params.Namespace = namespace
			// Don't log anything if it's a dry run so that the dry run output can easily be piped to other commands.
			if params.IsDryRun() {
				params.Writer = io.Discard
			}
			installer, err := install.NewK8sInstaller(k8sClient, params)
			if err != nil {
				return err
			}
			cmd.SilenceUsage = true
			if err := installer.UpgradeWithHelm(context.Background(), k8sClient); err != nil {
				fatalf("Unable to upgrade Cilium: %s", err)
			}
			return nil
		},
	}

	addCommonInstallFlags(cmd, &params)
	addCommonHelmFlags(cmd, &params)
	cmd.Flags().BoolVar(&params.HelmResetValues, "reset-values", false,
		"When upgrading, reset the helm values to the ones built into the chart")
	cmd.Flags().BoolVar(&params.HelmReuseValues, "reuse-values", false,
		"When upgrading, reuse the helm values from the latest release unless any overrides from are set from other flags. This option takes precedence over HelmResetValues")
	cmd.Flags().BoolVar(&params.DryRun, "dry-run", false,
		"Write resources to be installed to stdout without actually installing them")
	cmd.Flags().BoolVar(&params.DryRunHelmValues, "dry-run-helm-values", false,
		"Write non-default Helm values to stdout; without performing the actual upgrade")
	cmd.Flags().StringVar(&params.HelmRepository, "repository", defaults.HelmRepository, "Helm chart repository to download Cilium charts from")
	return cmd
}

func normalizeFlags(_ *pflag.FlagSet, name string) pflag.NormalizedName {
	switch name {
	case "helm-set":
		name = "set"
	case "helm-set-file":
		name = "set-file"
	case "helm-set-string":
		name = "set-string"
	case "helm-values":
		name = "values"
	}
	return pflag.NormalizedName(name)
}
