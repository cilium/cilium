// SPDX-License-Identifier: Apache-2.0
// Copyright 2020-2021 Authors of Cilium

package install

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/blang/semver/v4"
	ciliumhelm "github.com/cilium/charts"
	"github.com/cilium/cilium/api/v1/models"
	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/versioncheck"
	"helm.sh/helm/v3/pkg/action"
	"helm.sh/helm/v3/pkg/chart"
	"helm.sh/helm/v3/pkg/chart/loader"
	"helm.sh/helm/v3/pkg/cli/values"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	"github.com/cilium/cilium-cli/defaults"
	"github.com/cilium/cilium-cli/internal/certs"
	"github.com/cilium/cilium-cli/internal/k8s"
	"github.com/cilium/cilium-cli/internal/utils"
	"github.com/cilium/cilium-cli/status"
)

const (
	ipamKubernetes  = "kubernetes"
	ipamClusterPool = "cluster-pool"
	ipamENI         = "eni"
	ipamAzure       = "azure"
)

const (
	encryptionDisabled  = "disabled"
	encryptionIPsec     = "ipsec"
	encryptionWireguard = "wireguard"
)

func (k *K8sInstaller) generateAgentDaemonSet() *appsv1.DaemonSet {
	var (
		dsFilename string
	)

	ciliumVer := k.getCiliumVersion()
	switch {
	case versioncheck.MustCompile(">=1.9.0")(ciliumVer):
		dsFilename = "templates/cilium-agent/daemonset.yaml"
	}

	dsFile := k.manifests[dsFilename]

	var ds appsv1.DaemonSet
	utils.MustUnmarshalYAML([]byte(dsFile), &ds)
	return &ds
}

func (k *K8sInstaller) generateOperatorDeployment() *appsv1.Deployment {
	var (
		deployFilename string
	)

	ciliumVer := k.getCiliumVersion()
	switch {
	case versioncheck.MustCompile(">=1.9.0")(ciliumVer):
		deployFilename = "templates/cilium-operator/deployment.yaml"
	}

	deployFile := k.manifests[deployFilename]

	var deploy appsv1.Deployment
	utils.MustUnmarshalYAML([]byte(deployFile), &deploy)
	return &deploy
}

type k8sInstallerImplementation interface {
	ClusterName() string
	ListNodes(ctx context.Context, options metav1.ListOptions) (*corev1.NodeList, error)
	GetCiliumExternalWorkload(ctx context.Context, name string, opts metav1.GetOptions) (*ciliumv2.CiliumExternalWorkload, error)
	CreateCiliumExternalWorkload(ctx context.Context, cew *ciliumv2.CiliumExternalWorkload, opts metav1.CreateOptions) (*ciliumv2.CiliumExternalWorkload, error)
	DeleteCiliumExternalWorkload(ctx context.Context, name string, opts metav1.DeleteOptions) error
	ListCiliumExternalWorkloads(ctx context.Context, opts metav1.ListOptions) (*ciliumv2.CiliumExternalWorkloadList, error)
	CreateServiceAccount(ctx context.Context, namespace string, account *corev1.ServiceAccount, opts metav1.CreateOptions) (*corev1.ServiceAccount, error)
	DeleteServiceAccount(ctx context.Context, namespace, name string, opts metav1.DeleteOptions) error
	GetConfigMap(ctx context.Context, namespace, name string, opts metav1.GetOptions) (*corev1.ConfigMap, error)
	CreateConfigMap(ctx context.Context, namespace string, config *corev1.ConfigMap, opts metav1.CreateOptions) (*corev1.ConfigMap, error)
	DeleteConfigMap(ctx context.Context, namespace, name string, opts metav1.DeleteOptions) error
	CreateClusterRole(ctx context.Context, config *rbacv1.ClusterRole, opts metav1.CreateOptions) (*rbacv1.ClusterRole, error)
	DeleteClusterRole(ctx context.Context, name string, opts metav1.DeleteOptions) error
	CreateClusterRoleBinding(ctx context.Context, role *rbacv1.ClusterRoleBinding, opts metav1.CreateOptions) (*rbacv1.ClusterRoleBinding, error)
	DeleteClusterRoleBinding(ctx context.Context, name string, opts metav1.DeleteOptions) error
	CreateDaemonSet(ctx context.Context, namespace string, ds *appsv1.DaemonSet, opts metav1.CreateOptions) (*appsv1.DaemonSet, error)
	GetDaemonSet(ctx context.Context, namespace, name string, opts metav1.GetOptions) (*appsv1.DaemonSet, error)
	DeleteDaemonSet(ctx context.Context, namespace, name string, opts metav1.DeleteOptions) error
	PatchDaemonSet(ctx context.Context, namespace, name string, pt types.PatchType, data []byte, opts metav1.PatchOptions) (*appsv1.DaemonSet, error)
	GetService(ctx context.Context, namespace, name string, opts metav1.GetOptions) (*corev1.Service, error)
	CreateService(ctx context.Context, namespace string, service *corev1.Service, opts metav1.CreateOptions) (*corev1.Service, error)
	DeleteService(ctx context.Context, namespace, name string, opts metav1.DeleteOptions) error
	DeleteDeployment(ctx context.Context, namespace, name string, opts metav1.DeleteOptions) error
	CreateDeployment(ctx context.Context, namespace string, deployment *appsv1.Deployment, opts metav1.CreateOptions) (*appsv1.Deployment, error)
	GetDeployment(ctx context.Context, namespace, name string, opts metav1.GetOptions) (*appsv1.Deployment, error)
	PatchDeployment(ctx context.Context, namespace, name string, pt types.PatchType, data []byte, opts metav1.PatchOptions) (*appsv1.Deployment, error)
	CheckDeploymentStatus(ctx context.Context, namespace, deployment string) error
	DeleteNamespace(ctx context.Context, namespace string, opts metav1.DeleteOptions) error
	CreateNamespace(ctx context.Context, namespace string, opts metav1.CreateOptions) (*corev1.Namespace, error)
	GetNamespace(ctx context.Context, namespace string, options metav1.GetOptions) (*corev1.Namespace, error)
	ListPods(ctx context.Context, namespace string, options metav1.ListOptions) (*corev1.PodList, error)
	DeletePod(ctx context.Context, namespace, name string, options metav1.DeleteOptions) error
	ExecInPod(ctx context.Context, namespace, pod, container string, command []string) (bytes.Buffer, error)
	CreateSecret(ctx context.Context, namespace string, secret *corev1.Secret, opts metav1.CreateOptions) (*corev1.Secret, error)
	DeleteSecret(ctx context.Context, namespace, name string, opts metav1.DeleteOptions) error
	GetSecret(ctx context.Context, namespace, name string, opts metav1.GetOptions) (*corev1.Secret, error)
	PatchSecret(ctx context.Context, namespace, name string, pt types.PatchType, data []byte, opts metav1.PatchOptions) (*corev1.Secret, error)
	CreateResourceQuota(ctx context.Context, namespace string, r *corev1.ResourceQuota, opts metav1.CreateOptions) (*corev1.ResourceQuota, error)
	DeleteResourceQuota(ctx context.Context, namespace, name string, opts metav1.DeleteOptions) error
	AutodetectFlavor(ctx context.Context) (k8s.Flavor, error)
	ContextName() (name string)
	CiliumStatus(ctx context.Context, namespace, pod string) (*models.StatusResponse, error)
	ListCiliumEndpoints(ctx context.Context, namespace string, opts metav1.ListOptions) (*ciliumv2.CiliumEndpointList, error)
	GetRunningCiliumVersion(ctx context.Context, namespace string) (string, error)
	GetPlatform(ctx context.Context) (*k8s.Platform, error)
	GetServerVersion() (*semver.Version, error)
	CreateIngressClass(ctx context.Context, r *networkingv1.IngressClass, opts metav1.CreateOptions) (*networkingv1.IngressClass, error)
	DeleteIngressClass(ctx context.Context, name string, opts metav1.DeleteOptions) error
}

type K8sInstaller struct {
	client        k8sInstallerImplementation
	params        Parameters
	flavor        k8s.Flavor
	certManager   *certs.CertManager
	rollbackSteps []rollbackStep
	manifests     map[string]string
}

const (
	DatapathTunnel = "tunnel"
	DatapathAwsENI = "aws-eni"
	DatapathGKE    = "gke"
	DatapathAzure  = "azure"

	Microk8sSnapPath = "/var/snap/microk8s/current"
)

type AzureParameters struct {
	ResourceGroupName    string
	AKSNodeResourceGroup string
	SubscriptionName     string
	SubscriptionID       string
	TenantID             string
	ClientID             string
	ClientSecret         string
}

type Parameters struct {
	Namespace             string
	Writer                io.Writer
	ClusterName           string
	DisableChecks         []string
	Version               string
	AgentImage            string
	OperatorImage         string
	InheritCA             string
	Wait                  bool
	WaitDuration          time.Duration
	DatapathMode          string
	TunnelType            string
	IPv4NativeRoutingCIDR string
	ClusterID             int
	IPAM                  string
	KubeProxyReplacement  string
	Azure                 AzureParameters
	RestartUnmanagedPods  bool
	Encryption            string
	NodeEncryption        bool
	ConfigOverwrites      []string
	configOverwrites      map[string]string
	Rollback              bool

	// CiliumReadyTimeout defines the wait timeout for Cilium to become ready
	// after installing.
	CiliumReadyTimeout time.Duration

	// BaseVersion is used to explicitly specify Cilium version for generating the config map
	// in case it cannot be inferred from the Version field (e.g. commit SHA tags for CI images).
	BaseVersion string

	// K8sVersion is the Kubernetes version that will be used to generate the
	// kubernetes manifests. If the auto-detection fails, this flag can be used
	// as a workaround.
	K8sVersion string

	// HelmChartDirectory points to the location of a helm chart directory.
	// Useful to test from upstream where a helm release is not available yet.
	HelmChartDirectory string

	// HelmOpts are all the options the user used to pass into the Cilium cli
	// template.
	HelmOpts values.Options

	// HelmGenValuesFile points to the file that will store the generated helm
	// options.
	HelmGenValuesFile string
}

type rollbackStep func(context.Context)

func (p *Parameters) validate() error {
	p.configOverwrites = map[string]string{}
	for _, config := range p.ConfigOverwrites {
		t := strings.SplitN(config, "=", 2)
		if len(t) != 2 {
			return fmt.Errorf("invalid config overwrite %q, must be in the form key=valye", config)
		}

		p.configOverwrites[t[0]] = t[1]
	}
	if p.AgentImage != "" || p.OperatorImage != "" {
		return nil
	} else if !utils.CheckVersion(p.Version) && p.Version != "" {
		return fmt.Errorf("invalid syntax %q for image tag", p.Version)
	}

	return nil
}

func (k *K8sInstaller) fqAgentImage(imagePathMode utils.ImagePathMode) string {
	return utils.BuildImagePath(k.params.AgentImage, k.params.Version, defaults.AgentImage, defaults.Version, imagePathMode)
}

func (k *K8sInstaller) fqOperatorImage(imagePathMode utils.ImagePathMode) string {
	defaultImage := defaults.OperatorImage
	switch k.params.DatapathMode {
	case DatapathAwsENI:
		defaultImage = defaults.OperatorImageAWS
	case DatapathAzure:
		defaultImage = defaults.OperatorImageAzure
	}

	return utils.BuildImagePath(k.params.OperatorImage, k.params.Version, defaultImage, defaults.Version, imagePathMode)
}

func newHelmClient(namespace, k8sVersion string) (*action.Install, error) {
	actionConfig := new(action.Configuration)
	helmClient := action.NewInstall(actionConfig)
	helmClient.DryRun = true
	helmClient.ReleaseName = "release-name"
	helmClient.Replace = true // Skip the name check
	helmClient.ClientOnly = true
	helmClient.APIVersions = []string{k8sVersion}
	helmClient.Namespace = namespace

	return helmClient, nil
}

func newHelmChartFromCiliumVersion(ciliumVersion string) (*chart.Chart, error) {
	helmTgz, err := ciliumhelm.HelmFS.ReadFile(fmt.Sprintf("cilium-%s.tgz", ciliumVersion))
	if err != nil {
		return nil, fmt.Errorf("cilium version not found: %s", err)
	}

	// Check chart dependencies to make sure all are present in /charts
	return loader.LoadArchive(bytes.NewReader(helmTgz))
}

func newHelmChartFromDirectory(directory string) (*chart.Chart, error) {
	return loader.LoadDir(directory)
}

func NewK8sInstaller(client k8sInstallerImplementation, p Parameters) (*K8sInstaller, error) {
	if err := (&p).validate(); err != nil {
		return nil, fmt.Errorf("invalid parameters: %w", err)
	}

	cm := certs.NewCertManager(client, certs.Parameters{Namespace: p.Namespace})

	return &K8sInstaller{
		client:      client,
		params:      p,
		certManager: cm,
	}, nil
}

func (k *K8sInstaller) Log(format string, a ...interface{}) {
	fmt.Fprintf(k.params.Writer, format+"\n", a...)
}

func (k *K8sInstaller) Exec(command string, args ...string) ([]byte, error) {
	return utils.Exec(k, command, args...)
}

func (k *K8sInstaller) getCiliumVersion() semver.Version {
	v, err := utils.ParseCiliumVersion(k.params.Version, k.params.BaseVersion)
	if err != nil {
		v = versioncheck.MustVersion(defaults.Version)
		k.Log("Unable to parse the provided version %q, assuming %v for ConfigMap compatibility", k.params.Version, defaults.Version)
	}
	return v
}

func (k *K8sInstaller) generateConfigMap() (*corev1.ConfigMap, error) {
	var (
		cmFilename string
	)

	ciliumVer := k.getCiliumVersion()
	switch {
	case versioncheck.MustCompile(">=1.9.0")(ciliumVer):
		cmFilename = "templates/cilium-configmap.yaml"
	default:
		return nil, fmt.Errorf("cilium version unsupported %s", ciliumVer.String())
	}

	cmFile := k.manifests[cmFilename]

	var cm corev1.ConfigMap
	utils.MustUnmarshalYAML([]byte(cmFile), &cm)
	k.Log("🚀 Creating ConfigMap for Cilium version %s...", ciliumVer.String())

	for key, value := range k.params.configOverwrites {
		k.Log("ℹ️ Manual overwrite in ConfigMap: %s=%s", key, value)
		cm.Data[key] = value
	}

	if cm.Data["install-no-conntrack-iptables-rules"] == "true" {
		switch k.params.DatapathMode {
		case DatapathAwsENI:
			return nil, fmt.Errorf("--install-no-conntrack-iptables-rules cannot be enabled on AWS EKS")
		case DatapathGKE:
			return nil, fmt.Errorf("--install-no-conntrack-iptables-rules cannot be enabled on Google GKE")
		case DatapathAzure:
			return nil, fmt.Errorf("--install-no-conntrack-iptables-rules cannot be enabled on Azure AKS")
		}

		if cm.Data["tunnel"] != "disabled" {
			return nil, fmt.Errorf("--install-no-conntrack-iptables-rules requires tunneling to be disabled")
		}

		if cm.Data["kube-proxy-replacement"] != "strict" {
			return nil, fmt.Errorf("--install-no-conntrack-iptables-rules requires kube-proxy replacement to be enabled")
		}

		if cm.Data["enable-bpf-masquerade"] != "true" {
			return nil, fmt.Errorf("--install-no-conntrack-iptables-rules requires eBPF masquerading to be enabled")
		}

		if cm.Data["cni-chaining-mode"] != "" {
			return nil, fmt.Errorf("--install-no-conntrack-iptables-rules cannot be enabled with CNI chaining")
		}
	}

	return &cm, nil
}

func (k *K8sInstaller) deployResourceQuotas(ctx context.Context) error {
	k.Log("🚀 Creating Resource quotas...")

	ciliumResourceQuota := &corev1.ResourceQuota{
		ObjectMeta: metav1.ObjectMeta{
			Name: defaults.AgentResourceQuota,
		},
		Spec: corev1.ResourceQuotaSpec{
			Hard: corev1.ResourceList{
				// 5k nodes * 2 DaemonSets (Cilium and cilium node init)
				corev1.ResourcePods: resource.MustParse("10k"),
			},
			ScopeSelector: &corev1.ScopeSelector{
				MatchExpressions: []corev1.ScopedResourceSelectorRequirement{
					{
						ScopeName: corev1.ResourceQuotaScopePriorityClass,
						Operator:  corev1.ScopeSelectorOpIn,
						Values:    []string{"system-node-critical"},
					},
				},
			},
		},
	}

	if _, err := k.client.CreateResourceQuota(ctx, k.params.Namespace, ciliumResourceQuota, metav1.CreateOptions{}); err != nil {
		return err
	}
	k.pushRollbackStep(func(ctx context.Context) {
		if err := k.client.DeleteResourceQuota(ctx, k.params.Namespace, defaults.AgentResourceQuota, metav1.DeleteOptions{}); err != nil {
			k.Log("Cannot delete %s ResourceQuota: %s", defaults.AgentResourceQuota, err)
		}
	})

	operatorResourceQuota := &corev1.ResourceQuota{
		ObjectMeta: metav1.ObjectMeta{
			Name: defaults.OperatorResourceQuota,
		},
		Spec: corev1.ResourceQuotaSpec{
			Hard: corev1.ResourceList{
				// 15 "clusterwide" Cilium Operator pods for HA
				corev1.ResourcePods: resource.MustParse("15"),
			},
			ScopeSelector: &corev1.ScopeSelector{
				MatchExpressions: []corev1.ScopedResourceSelectorRequirement{
					{
						ScopeName: corev1.ResourceQuotaScopePriorityClass,
						Operator:  corev1.ScopeSelectorOpIn,
						Values:    []string{"system-cluster-critical"},
					},
				},
			},
		},
	}

	if _, err := k.client.CreateResourceQuota(ctx, k.params.Namespace, operatorResourceQuota, metav1.CreateOptions{}); err != nil {
		return err
	}
	k.pushRollbackStep(func(ctx context.Context) {
		if err := k.client.DeleteResourceQuota(ctx, k.params.Namespace, defaults.OperatorResourceQuota, metav1.DeleteOptions{}); err != nil {
			k.Log("Cannot delete %s ResourceQuota: %s", defaults.OperatorResourceQuota, err)
		}
	})

	return nil
}

func (k *K8sInstaller) restartUnmanagedPods(ctx context.Context) error {
	var printed bool

	pods, err := k.client.ListPods(ctx, "", metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("unable to list pods: %w", err)
	}

	// If not pods are running, skip. This avoids attemptingm to retrieve
	// CiliumEndpoints if no pods are present at all. Cilium will not be
	// running either.
	if len(pods.Items) == 0 {
		return nil
	}

	cepMap := map[string]struct{}{}
	ceps, err := k.client.ListCiliumEndpoints(ctx, "", metav1.ListOptions{})
	if err != nil {
		// When the CEP has not been registered yet, it's impossible
		// for any pods to be managed by Cilium.
		if err.Error() != "the server could not find the requested resource (get ciliumendpoints.cilium.io)" {
			return fmt.Errorf("unable to list cilium endpoints: %w", err)
		}
	} else {
		for _, cep := range ceps.Items {
			cepMap[cep.Namespace+"/"+cep.Name] = struct{}{}
		}
	}

	for _, pod := range pods.Items {
		// PodSucceeded means that all containers in the pod have voluntarily terminated
		// with a container exit code of 0, and the system is not going to restart any of these containers.
		if pod.Status.Phase == corev1.PodSucceeded {
			continue
		}
		if !pod.Spec.HostNetwork {
			if _, ok := cepMap[pod.Namespace+"/"+pod.Name]; ok {
				continue
			}

			if !printed {
				k.Log("♻️  Restarting unmanaged pods...")
				printed = true
			}
			err := k.client.DeletePod(ctx, pod.Namespace, pod.Name, metav1.DeleteOptions{})
			if err != nil {
				k.Log("⚠️  Unable to restart pod %s/%s: %s", pod.Namespace, pod.Name, err)
			} else {
				k.Log("♻️  Restarted unmanaged pod %s/%s", pod.Namespace, pod.Name)
			}
		}
	}

	return nil

}

func (k *K8sInstaller) Install(ctx context.Context) error {
	if err := k.autodetectAndValidate(ctx); err != nil {
		return err
	}

	switch k.flavor.Kind {
	case k8s.KindEKS:
		if _, err := k.client.GetDaemonSet(ctx, AwsNodeDaemonSetNamespace, AwsNodeDaemonSetName, metav1.GetOptions{}); err == nil {
			k.Log("🔥 Patching the %q DaemonSet to evict its pods...", AwsNodeDaemonSetName)
			patch := []byte(fmt.Sprintf(`{"spec":{"template":{"spec":{"nodeSelector":{"%s":"%s"}}}}}`, AwsNodeDaemonSetNodeSelectorKey, AwsNodeDaemonSetNodeSelectorValue))
			if _, err := k.client.PatchDaemonSet(ctx, AwsNodeDaemonSetNamespace, AwsNodeDaemonSetName, types.StrategicMergePatchType, patch, metav1.PatchOptions{}); err != nil {
				k.Log("❌ Unable to patch the %q DaemonSet", AwsNodeDaemonSetName)
				return err
			}
		}
	case k8s.KindGKE:
		if k.params.IPv4NativeRoutingCIDR == "" {
			cidr, err := k.gkeNativeRoutingCIDR(ctx, k.client.ContextName())
			if err != nil {
				k.Log("❌ Unable to auto-detect GKE native routing CIDR. Is \"gcloud\" installed?")
				k.Log("ℹ️  You can set the native routing CIDR manually with --ipv4-native-routing-cidr")
				return err
			}
			k.params.IPv4NativeRoutingCIDR = cidr
		}

	case k8s.KindAKS:
		if err := k.aksSetup(ctx); err != nil {
			return err
		}
	}

	err := k.generateManifests(ctx)
	if err != nil {
		return err
	}

	if k.params.HelmGenValuesFile != "" {
		k.Log("ℹ️  Generated helm values file %q successfully written", k.params.HelmGenValuesFile)
		return nil
	}

	switch k.flavor.Kind {
	case k8s.KindGKE:
		// TODO(aanm) automate this as well in form of helm chart
		if err := k.deployResourceQuotas(ctx); err != nil {
			return err
		}

	case k8s.KindAKS:
		// We only made the secret-based azure installation available in >= 1.12.0
		// Introduced in https://github.com/cilium/cilium/pull/18010
		ciliumVer := k.getCiliumVersion()
		switch {
		case versioncheck.MustCompile(">=1.12.0")(ciliumVer):
			if err := k.createAKSSecrets(ctx); err != nil {
				return err
			}
		}
	}

	if err := k.installCerts(ctx); err != nil {
		return err
	}

	k.Log("🚀 Creating Service accounts...")
	if _, err := k.client.CreateServiceAccount(ctx, k.params.Namespace, k.NewServiceAccount(defaults.AgentServiceAccountName), metav1.CreateOptions{}); err != nil {
		return err
	}
	k.pushRollbackStep(func(ctx context.Context) {
		if err := k.client.DeleteServiceAccount(ctx, k.params.Namespace, defaults.AgentServiceAccountName, metav1.DeleteOptions{}); err != nil {
			k.Log("Cannot delete %s ServiceAccount: %s", defaults.AgentServiceAccountName, err)
		}
	})

	if _, err := k.client.CreateServiceAccount(ctx, k.params.Namespace, k.NewServiceAccount(defaults.OperatorServiceAccountName), metav1.CreateOptions{}); err != nil {
		return err
	}
	k.pushRollbackStep(func(ctx context.Context) {
		if err := k.client.DeleteServiceAccount(ctx, k.params.Namespace, defaults.OperatorServiceAccountName, metav1.DeleteOptions{}); err != nil {
			k.Log("Cannot delete %s ServiceAccount: %s", defaults.OperatorServiceAccountName, err)
		}
	})

	k.Log("🚀 Creating Cluster roles...")
	if _, err := k.client.CreateClusterRole(ctx, k.NewClusterRole(defaults.AgentClusterRoleName), metav1.CreateOptions{}); err != nil {
		return err
	}
	k.pushRollbackStep(func(ctx context.Context) {
		if err := k.client.DeleteClusterRole(ctx, defaults.AgentClusterRoleName, metav1.DeleteOptions{}); err != nil {
			k.Log("Cannot delete %s ClusterRole: %s", defaults.AgentClusterRoleName, err)
		}
	})

	if _, err := k.client.CreateClusterRoleBinding(ctx, k.NewClusterRoleBinding(defaults.AgentClusterRoleName), metav1.CreateOptions{}); err != nil {
		return err
	}
	k.pushRollbackStep(func(ctx context.Context) {
		if err := k.client.DeleteClusterRoleBinding(ctx, defaults.AgentClusterRoleName, metav1.DeleteOptions{}); err != nil {
			k.Log("Cannot delete %s ClusterRoleBinding: %s", defaults.AgentClusterRoleName, err)
		}
	})

	if _, err := k.client.CreateClusterRole(ctx, k.NewClusterRole(defaults.OperatorClusterRoleName), metav1.CreateOptions{}); err != nil {
		return err
	}
	k.pushRollbackStep(func(ctx context.Context) {
		if err := k.client.DeleteClusterRole(ctx, defaults.OperatorClusterRoleName, metav1.DeleteOptions{}); err != nil {
			k.Log("Cannot delete %s ClusterRole: %s", defaults.OperatorClusterRoleName, err)
		}
	})

	if _, err := k.client.CreateClusterRoleBinding(ctx, k.NewClusterRoleBinding(defaults.OperatorClusterRoleName), metav1.CreateOptions{}); err != nil {
		return err
	}
	k.pushRollbackStep(func(ctx context.Context) {
		if err := k.client.DeleteClusterRoleBinding(ctx, defaults.OperatorClusterRoleName, metav1.DeleteOptions{}); err != nil {
			k.Log("Cannot delete %s ClusterRoleBinding: %s", defaults.OperatorClusterRoleName, err)
		}
	})

	if k.params.Encryption == encryptionIPsec {
		// TODO(aanm) automate this as well in form of helm chart
		if err := k.createEncryptionSecret(ctx); err != nil {
			return err
		}
	}

	if _, err := k.client.CreateIngressClass(ctx, k8s.NewIngressClass(defaults.IngressClassName, defaults.IngressControllerName), metav1.CreateOptions{}); err != nil {
		return err
	}
	k.pushRollbackStep(func(ctx context.Context) {
		if err := k.client.DeleteIngressClass(ctx, defaults.IngressClassName, metav1.DeleteOptions{}); err != nil {
			k.Log("Cannot delete %s IngressClass: %s", defaults.IngressClassName, err)
		}
	})

	configMap, err := k.generateConfigMap()
	if err != nil {
		return fmt.Errorf("cannot generate ConfigMap: %w", err)
	}

	if _, err := k.client.CreateConfigMap(ctx, k.params.Namespace, configMap, metav1.CreateOptions{}); err != nil {
		return err
	}
	k.pushRollbackStep(func(ctx context.Context) {
		if err := k.client.DeleteConfigMap(ctx, k.params.Namespace, defaults.ConfigMapName, metav1.DeleteOptions{}); err != nil {
			k.Log("Cannot delete %s ConfigMap: %s", defaults.ConfigMapName, err)
		}
	})

	// Create the node-init daemonset if one is required for the current kind.
	if _, exists := nodeInitScript[k.flavor.Kind]; exists {
		k.Log("🚀 Creating %s Node Init DaemonSet...", k.flavor.Kind.String())
		ds := k.generateNodeInitDaemonSet(k.flavor.Kind)
		if _, err := k.client.CreateDaemonSet(ctx, k.params.Namespace, ds, metav1.CreateOptions{}); err != nil {
			return err
		}
		k.pushRollbackStep(func(ctx context.Context) {
			if err := k.client.DeleteDaemonSet(ctx, k.params.Namespace, ds.Name, metav1.DeleteOptions{}); err != nil {
				k.Log("Cannot delete %s DaemonSet: %s", ds.Name, err)
			}
		})
	}

	k.Log("🚀 Creating Agent DaemonSet...")
	if _, err := k.client.CreateDaemonSet(ctx, k.params.Namespace, k.generateAgentDaemonSet(), metav1.CreateOptions{}); err != nil {
		return err
	}
	k.pushRollbackStep(func(ctx context.Context) {
		if err := k.client.DeleteDaemonSet(ctx, k.params.Namespace, defaults.AgentDaemonSetName, metav1.DeleteOptions{}); err != nil {
			k.Log("Cannot delete %s DaemonSet: %s", defaults.AgentDaemonSetName, err)
		}
	})

	k.Log("🚀 Creating Operator Deployment...")
	if _, err := k.client.CreateDeployment(ctx, k.params.Namespace, k.generateOperatorDeployment(), metav1.CreateOptions{}); err != nil {
		return err
	}
	k.pushRollbackStep(func(ctx context.Context) {
		if err := k.client.DeleteDeployment(ctx, k.params.Namespace, defaults.OperatorDeploymentName, metav1.DeleteOptions{}); err != nil {
			k.Log("Cannot delete %s Deployment: %s", defaults.OperatorDeploymentName, err)
		}
	})

	if k.params.Wait || k.params.RestartUnmanagedPods {
		// In case unmanaged pods should be restarted we need to make sure that Cilium
		// DaemonSet is up and running to guarantee the CNI configuration and binary
		// are deployed on the node.  See https://github.com/cilium/cilium/issues/14128
		// for details.
		k.Log("⌛ Waiting for Cilium to be installed and ready...")
		collector, err := status.NewK8sStatusCollector(k.client, status.K8sStatusParameters{
			Namespace:       k.params.Namespace,
			Wait:            true,
			WaitDuration:    k.params.WaitDuration,
			WarningFreePods: []string{defaults.AgentDaemonSetName, defaults.OperatorDeploymentName},
		})
		if err != nil {
			return err
		}

		s, err := collector.Status(ctx)
		if err != nil {
			fmt.Print(s.Format())
			return err
		}
	}

	if k.params.RestartUnmanagedPods {
		if err := k.restartUnmanagedPods(ctx); err != nil {
			return err
		}
	}

	k.Log("✅ Cilium was successfully installed! Run 'cilium status' to view installation health")

	return nil
}

func (k *K8sInstaller) pushRollbackStep(step rollbackStep) {
	// Prepend the step to the steps slice so that, in case rollback is
	// performed, steps are rolled back in the reverse order
	k.rollbackSteps = append([]rollbackStep{step}, k.rollbackSteps...)
}

func (k *K8sInstaller) RollbackInstallation(ctx context.Context) {
	if !k.params.Rollback {
		k.Log("ℹ️  Rollback disabled with '--rollback=false', leaving installed resources behind")
		return
	}
	k.Log("↩️ Rolling back installation...")

	for _, r := range k.rollbackSteps {
		r(ctx)
	}
}
