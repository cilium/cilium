// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package install

import (
	"context"
	"fmt"
	"io"
	"time"

	"github.com/blang/semver/v4"
	"helm.sh/helm/v3/pkg/action"
	"helm.sh/helm/v3/pkg/chart"
	"helm.sh/helm/v3/pkg/cli"
	"helm.sh/helm/v3/pkg/cli/values"
	"helm.sh/helm/v3/pkg/getter"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/yaml"

	"github.com/cilium/cilium-cli/defaults"
	"github.com/cilium/cilium-cli/internal/helm"
	"github.com/cilium/cilium-cli/internal/utils"
	"github.com/cilium/cilium-cli/k8s"
)

const (
	DatapathTunnel    = "tunnel"
	DatapathNative    = "native"
	DatapathAwsENI    = "aws-eni"
	DatapathGKE       = "gke"
	DatapathAzure     = "azure"
	DatapathAKSBYOCNI = "aks-byocni"
)

const (
	ipamKubernetes  = "kubernetes"
	ipamClusterPool = "cluster-pool"
	ipamENI         = "eni"
	ipamAzure       = "azure"
)

const (
	tunnelDisabled = "disabled"
	tunnelVxlan    = "vxlan"
)

const (
	routingModeNative = "native"
	routingModeTunnel = "tunnel"
)

const (
	Microk8sSnapPath = "/var/snap/microk8s/current"
)

type k8sInstallerImplementation interface {
	GetAPIServerHostAndPort() (string, string)
	ListDaemonSet(ctx context.Context, namespace string, o metav1.ListOptions) (*appsv1.DaemonSetList, error)
	GetDaemonSet(ctx context.Context, namespace, name string, opts metav1.GetOptions) (*appsv1.DaemonSet, error)
	PatchDaemonSet(ctx context.Context, namespace, name string, pt types.PatchType, data []byte, opts metav1.PatchOptions) (*appsv1.DaemonSet, error)
	GetEndpoints(ctx context.Context, namespace, name string, opts metav1.GetOptions) (*corev1.Endpoints, error)
	AutodetectFlavor(ctx context.Context) k8s.Flavor
	ContextName() (name string)
}

type K8sInstaller struct {
	client       k8sInstallerImplementation
	params       Parameters
	flavor       k8s.Flavor
	chartVersion semver.Version
	chart        *chart.Chart
}

type AzureParameters struct {
	ResourceGroupName    string
	AKSNodeResourceGroup string
	SubscriptionName     string
	SubscriptionID       string
	TenantID             string
	ClientID             string
	ClientSecret         string
	IsBYOCNI             bool
}

type Parameters struct {
	Namespace             string
	Writer                io.Writer
	ClusterName           string
	DisableChecks         []string
	Version               string
	Wait                  bool
	WaitDuration          time.Duration
	DatapathMode          string
	IPv4NativeRoutingCIDR string
	Azure                 AzureParameters

	// HelmChartDirectory points to the location of a helm chart directory.
	// Useful to test from upstream where a helm release is not available yet.
	HelmChartDirectory string

	// HelmOpts are all the options the user used to pass into the Cilium cli
	// template.
	HelmOpts values.Options

	// HelmResetValues if true, will reset helm values to the defaults found in the chart when upgrading
	HelmResetValues bool

	// HelmReuseValues if true, will reuse the helm values from the latest release when upgrading, unless overrides are
	// specified by other flags. This options take precedence over the HelmResetValues option.
	HelmReuseValues bool

	// ListVersions lists all the available versions for install without actually installing.
	ListVersions bool

	// NodesWithoutCilium lists all nodes on which Cilium is not installed.
	NodesWithoutCilium []string

	// DryRun writes resources to be installed to stdout without actually installing them. For Helm
	// installation mode only.
	DryRun bool

	// DryRunHelmValues writes non-default Helm values to stdout without performing the actual installation.
	// For Helm installation mode only.
	DryRunHelmValues bool

	// HelmRepository specifies the Helm repository to download Cilium Helm charts from.
	HelmRepository string
}

func (p *Parameters) IsDryRun() bool {
	return p.DryRun || p.DryRunHelmValues
}

func NewK8sInstaller(client k8sInstallerImplementation, p Parameters) (*K8sInstaller, error) {
	chartVersion, helmChart, err := helm.ResolveHelmChartVersion(p.Version, p.HelmChartDirectory, p.HelmRepository)
	if err != nil {
		return nil, err
	}

	return &K8sInstaller{
		client:       client,
		params:       p,
		chartVersion: chartVersion,
		chart:        helmChart,
	}, nil
}

func (k *K8sInstaller) Log(format string, a ...interface{}) {
	fmt.Fprintf(k.params.Writer, format+"\n", a...)
}

func (k *K8sInstaller) Exec(command string, args ...string) ([]byte, error) {
	return utils.Exec(k, command, args...)
}

func (k *K8sInstaller) listVersions() error {
	// Print available versions and return.
	versions, err := helm.ListVersions()
	if err != nil {
		return err
	}
	// Iterate backwards to print the newest version first.
	for i := len(versions) - 1; i >= 0; i-- {
		version := "v" + versions[i].String()
		if version == defaults.Version {
			fmt.Println(version, "(default)")
		} else {
			fmt.Println(version)
		}
	}
	return err
}

func getChainingMode(values map[string]interface{}) string {
	chainingMode, _, _ := unstructured.NestedString(values, "cni", "chainingMode")
	return chainingMode
}

func (k *K8sInstaller) preinstall(ctx context.Context) error {
	// TODO (ajs): Note that we have our own implementation of helm MergeValues at internal/helm/MergeValues, used
	//  e.g. in hubble.go. Does using the upstream HelmOpts.MergeValues here create inconsistencies with which
	//  parameters take precedence? Test and determine which we should use here for expected behavior.
	// Get Helm values to check if ipv4NativeRoutingCIDR value is specified via a Helm flag.
	helmValues, err := k.params.HelmOpts.MergeValues(getter.All(cli.New()))
	if err != nil {
		return err
	}

	if err := k.autodetectAndValidate(ctx, helmValues); err != nil {
		return err
	}

	switch k.flavor.Kind {
	case k8s.KindGKE:
		if k.params.IPv4NativeRoutingCIDR == "" && helmValues["ipv4NativeRoutingCIDR"] == nil {
			cidr, err := k.gkeNativeRoutingCIDR(k.client.ContextName())
			if err != nil {
				k.Log("❌ Unable to auto-detect GKE native routing CIDR. Is \"gcloud\" installed?")
				k.Log("ℹ️  You can set the native routing CIDR manually with --set ipv4NativeRoutingCIDR=x.x.x.x/x")
				return err
			}
			k.params.IPv4NativeRoutingCIDR = cidr
		}

	case k8s.KindAKS:
		if k.params.DatapathMode == DatapathAzure {
			// The Azure Service Principal is only needed when using Azure IPAM
			if err := k.azureSetupServicePrincipal(); err != nil {
				return err
			}
		}
	case k8s.KindEKS:
		chainingMode := getChainingMode(helmValues)

		// Do not stop AWS DS if we are running in chaining mode
		if chainingMode != "aws-cni" && !k.params.IsDryRun() {
			if _, err := k.client.GetDaemonSet(ctx, AwsNodeDaemonSetNamespace, AwsNodeDaemonSetName, metav1.GetOptions{}); err == nil {
				k.Log("🔥 Patching the %q DaemonSet to evict its pods...", AwsNodeDaemonSetName)
				patch := []byte(fmt.Sprintf(`{"spec":{"template":{"spec":{"nodeSelector":{"%s":"%s"}}}}}`, AwsNodeDaemonSetNodeSelectorKey, AwsNodeDaemonSetNodeSelectorValue))
				if _, err := k.client.PatchDaemonSet(ctx, AwsNodeDaemonSetNamespace, AwsNodeDaemonSetName, types.StrategicMergePatchType, patch, metav1.PatchOptions{}); err != nil {
					k.Log("❌ Unable to patch the %q DaemonSet", AwsNodeDaemonSetName)
					return err
				}
			}
		}
	}

	return nil
}

func (k *K8sInstaller) InstallWithHelm(ctx context.Context, k8sClient *k8s.Client) error {
	if k.params.ListVersions {
		return k.listVersions()
	}
	if err := k.preinstall(ctx); err != nil {
		return err
	}
	vals, err := k.getHelmValues()
	if err != nil {
		return err
	}
	helmClient := action.NewInstall(k8sClient.HelmActionConfig)
	helmClient.ReleaseName = defaults.HelmReleaseName
	helmClient.Namespace = k.params.Namespace
	helmClient.Wait = k.params.Wait
	helmClient.Timeout = k.params.WaitDuration
	helmClient.DryRun = k.params.IsDryRun()
	release, err := helmClient.RunWithContext(ctx, k.chart, vals)
	if err != nil {
		return err
	}
	if k.params.DryRun {
		fmt.Println(release.Manifest)
	}
	if k.params.DryRunHelmValues {
		helmValues, err := yaml.Marshal(release.Config)
		if err != nil {
			return err
		}
		fmt.Println(string(helmValues))
	}
	return err
}
