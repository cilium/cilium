// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package k8s

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/blang/semver/v4"
	"helm.sh/helm/v3/pkg/action"
	"helm.sh/helm/v3/pkg/cli/output"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apiextensions "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	apiextensionsclientset "k8s.io/apiextensions-apiserver/pkg/client/clientset/clientset"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/strategicpatch"
	"k8s.io/cli-runtime/pkg/genericclioptions"
	"k8s.io/cli-runtime/pkg/resource"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/scheme"
	_ "k8s.io/client-go/plugin/pkg/client/auth" // Register all auth providers (azure, gcp, oidc, openstack, ..).
	"k8s.io/client-go/rest"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"

	"github.com/cilium/cilium/api/v1/models"
	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	ciliumv2alpha1 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	ciliumClientset "github.com/cilium/cilium/pkg/k8s/client/clientset/versioned"
	"github.com/cilium/cilium/pkg/versioncheck"

	"github.com/cilium/cilium-cli/defaults"
)

type Client struct {
	Clientset          kubernetes.Interface
	ExtensionClientset apiextensionsclientset.Interface // k8s api extension needed to retrieve CRDs
	DynamicClientset   dynamic.Interface
	CiliumClientset    ciliumClientset.Interface
	Config             *rest.Config
	RawConfig          clientcmdapi.Config
	RESTClientGetter   genericclioptions.RESTClientGetter
	contextName        string
	HelmActionConfig   *action.Configuration
}

func NewClient(contextName, kubeconfig, ciliumNamespace string) (*Client, error) {
	// Register the Cilium types in the default scheme.
	_ = ciliumv2.AddToScheme(scheme.Scheme)
	_ = ciliumv2alpha1.AddToScheme(scheme.Scheme)

	restClientGetter := genericclioptions.ConfigFlags{
		Context:    &contextName,
		KubeConfig: &kubeconfig,
	}
	rawKubeConfigLoader := restClientGetter.ToRawKubeConfigLoader()

	config, err := rawKubeConfigLoader.ClientConfig()
	if err != nil {
		return nil, err
	}

	rawConfig, err := rawKubeConfigLoader.RawConfig()
	if err != nil {
		return nil, err
	}

	ciliumClientset, err := ciliumClientset.NewForConfig(config)
	if err != nil {
		return nil, err
	}

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, err
	}

	extensionClientset, err := apiextensionsclientset.NewForConfig(config)
	if err != nil {
		return nil, err
	}

	dynamicClientset, err := dynamic.NewForConfig(config)
	if err != nil {
		return nil, err
	}

	if contextName == "" {
		contextName = rawConfig.CurrentContext
	}

	// Initialize Helm action configuration.
	// Use the default Helm driver (Kubernetes secret).
	helmDriver := ""
	actionConfig := action.Configuration{}
	logger := func(_ string, _ ...interface{}) {}
	if err := actionConfig.Init(&restClientGetter, ciliumNamespace, helmDriver, logger); err != nil {
		return nil, err
	}

	return &Client{
		CiliumClientset:    ciliumClientset,
		Clientset:          clientset,
		ExtensionClientset: extensionClientset,
		Config:             config,
		DynamicClientset:   dynamicClientset,
		RawConfig:          rawConfig,
		RESTClientGetter:   &restClientGetter,
		contextName:        contextName,
		HelmActionConfig:   &actionConfig,
	}, nil
}

// ContextName returns the name of the context the client is connected to
func (c *Client) ContextName() (name string) {
	return c.contextName
}

// ClusterName returns the name of the cluster the client is connected to
func (c *Client) ClusterName() (name string) {
	if context, ok := c.RawConfig.Contexts[c.ContextName()]; ok {
		name = context.Cluster
	}
	return
}

func (c *Client) GetAPIServerHostAndPort() (string, string) {
	if context, ok := c.RawConfig.Contexts[c.ContextName()]; ok {
		addr := c.RawConfig.Clusters[context.Cluster].Server
		if addr != "" {
			url, err := url.Parse(addr)
			if err == nil {
				host, port, _ := net.SplitHostPort(url.Host)
				return host, port
			}
		}
	}
	return "", ""
}

func (c *Client) CreateSecret(ctx context.Context, namespace string, secret *corev1.Secret, opts metav1.CreateOptions) (*corev1.Secret, error) {
	return c.Clientset.CoreV1().Secrets(namespace).Create(ctx, secret, opts)
}

func (c *Client) UpdateSecret(ctx context.Context, namespace string, secret *corev1.Secret, opts metav1.UpdateOptions) (*corev1.Secret, error) {
	return c.Clientset.CoreV1().Secrets(namespace).Update(ctx, secret, opts)
}

func (c *Client) PatchSecret(ctx context.Context, namespace, name string, pt types.PatchType, data []byte, opts metav1.PatchOptions) (*corev1.Secret, error) {
	return c.Clientset.CoreV1().Secrets(namespace).Patch(ctx, name, pt, data, opts)
}

func (c *Client) DeleteSecret(ctx context.Context, namespace, name string, opts metav1.DeleteOptions) error {
	return c.Clientset.CoreV1().Secrets(namespace).Delete(ctx, name, opts)
}

func (c *Client) GetSecret(ctx context.Context, namespace, name string, opts metav1.GetOptions) (*corev1.Secret, error) {
	return c.Clientset.CoreV1().Secrets(namespace).Get(ctx, name, opts)
}

func (c *Client) CreateServiceAccount(ctx context.Context, namespace string, account *corev1.ServiceAccount, opts metav1.CreateOptions) (*corev1.ServiceAccount, error) {
	return c.Clientset.CoreV1().ServiceAccounts(namespace).Create(ctx, account, opts)
}

func (c *Client) DeleteServiceAccount(ctx context.Context, namespace, name string, opts metav1.DeleteOptions) error {
	return c.Clientset.CoreV1().ServiceAccounts(namespace).Delete(ctx, name, opts)
}

func (c *Client) GetClusterRole(ctx context.Context, name string, opts metav1.GetOptions) (*rbacv1.ClusterRole, error) {
	return c.Clientset.RbacV1().ClusterRoles().Get(ctx, name, opts)
}

func (c *Client) GetConfigMap(ctx context.Context, namespace, name string, opts metav1.GetOptions) (*corev1.ConfigMap, error) {
	return c.Clientset.CoreV1().ConfigMaps(namespace).Get(ctx, name, opts)
}

func (c *Client) PatchConfigMap(ctx context.Context, namespace, name string, pt types.PatchType, data []byte, opts metav1.PatchOptions) (*corev1.ConfigMap, error) {
	return c.Clientset.CoreV1().ConfigMaps(namespace).Patch(ctx, name, pt, data, opts)
}

func (c *Client) CreateService(ctx context.Context, namespace string, service *corev1.Service, opts metav1.CreateOptions) (*corev1.Service, error) {
	return c.Clientset.CoreV1().Services(namespace).Create(ctx, service, opts)
}

func (c *Client) DeleteService(ctx context.Context, namespace, name string, opts metav1.DeleteOptions) error {
	return c.Clientset.CoreV1().Services(namespace).Delete(ctx, name, opts)
}

func (c *Client) GetService(ctx context.Context, namespace, name string, opts metav1.GetOptions) (*corev1.Service, error) {
	return c.Clientset.CoreV1().Services(namespace).Get(ctx, name, opts)
}

func (c *Client) GetEndpoints(ctx context.Context, namespace, name string, opts metav1.GetOptions) (*corev1.Endpoints, error) {
	return c.Clientset.CoreV1().Endpoints(namespace).Get(ctx, name, opts)
}

func (c *Client) CreateDeployment(ctx context.Context, namespace string, deployment *appsv1.Deployment, opts metav1.CreateOptions) (*appsv1.Deployment, error) {
	return c.Clientset.AppsV1().Deployments(namespace).Create(ctx, deployment, opts)
}

func (c *Client) GetDeployment(ctx context.Context, namespace, name string, opts metav1.GetOptions) (*appsv1.Deployment, error) {
	return c.Clientset.AppsV1().Deployments(namespace).Get(ctx, name, opts)
}

func (c *Client) DeleteDeployment(ctx context.Context, namespace, name string, opts metav1.DeleteOptions) error {
	return c.Clientset.AppsV1().Deployments(namespace).Delete(ctx, name, opts)
}

func (c *Client) CheckDeploymentStatus(ctx context.Context, namespace, deployment string) error {
	d, err := c.GetDeployment(ctx, namespace, deployment, metav1.GetOptions{})
	if err != nil {
		return err
	}

	if d == nil {
		return fmt.Errorf("deployment is not available")
	}

	if d.Status.ObservedGeneration != d.Generation {
		return fmt.Errorf("observed generation (%d) is older than generation of the desired state (%d)",
			d.Status.ObservedGeneration, d.Generation)
	}

	if d.Status.Replicas == 0 {
		return fmt.Errorf("replicas count is zero")
	}

	if d.Status.AvailableReplicas != d.Status.Replicas {
		return fmt.Errorf("only %d of %d replicas are available", d.Status.AvailableReplicas, d.Status.Replicas)
	}

	if d.Status.ReadyReplicas != d.Status.Replicas {
		return fmt.Errorf("only %d of %d replicas are ready", d.Status.ReadyReplicas, d.Status.Replicas)
	}

	if d.Status.UpdatedReplicas != d.Status.Replicas {
		return fmt.Errorf("only %d of %d replicas are up-to-date", d.Status.UpdatedReplicas, d.Status.Replicas)
	}

	return nil
}

func (c *Client) CreateNamespace(ctx context.Context, namespace *corev1.Namespace, opts metav1.CreateOptions) (*corev1.Namespace, error) {
	return c.Clientset.CoreV1().Namespaces().Create(ctx, namespace, opts)
}

func (c *Client) GetNamespace(ctx context.Context, namespace string, options metav1.GetOptions) (*corev1.Namespace, error) {
	return c.Clientset.CoreV1().Namespaces().Get(ctx, namespace, options)
}

func (c *Client) DeleteNamespace(ctx context.Context, namespace string, opts metav1.DeleteOptions) error {
	return c.Clientset.CoreV1().Namespaces().Delete(ctx, namespace, opts)
}

func (c *Client) GetPod(ctx context.Context, namespace, name string, opts metav1.GetOptions) (*corev1.Pod, error) {
	return c.Clientset.CoreV1().Pods(namespace).Get(ctx, name, opts)
}

func (c *Client) GetRaw(ctx context.Context, path string) (string, error) {
	result := c.Clientset.CoreV1().RESTClient().Get().AbsPath(path).Do(ctx)

	response, err := result.Raw()
	if err != nil {
		return "", err
	}
	return string(response), nil

}

func (c *Client) CreatePod(ctx context.Context, namespace string, pod *corev1.Pod, opts metav1.CreateOptions) (*corev1.Pod, error) {
	return c.Clientset.CoreV1().Pods(namespace).Create(ctx, pod, opts)
}

func (c *Client) DeletePod(ctx context.Context, namespace, name string, opts metav1.DeleteOptions) error {
	return c.Clientset.CoreV1().Pods(namespace).Delete(ctx, name, opts)
}

func (c *Client) DeletePodCollection(ctx context.Context, namespace string, opts metav1.DeleteOptions, listOpts metav1.ListOptions) error {
	return c.Clientset.CoreV1().Pods(namespace).DeleteCollection(ctx, opts, listOpts)
}

func (c *Client) ListPods(ctx context.Context, namespace string, options metav1.ListOptions) (*corev1.PodList, error) {
	return c.Clientset.CoreV1().Pods(namespace).List(ctx, options)
}

func (c *Client) PodLogs(namespace, name string, opts *corev1.PodLogOptions) *rest.Request {
	return c.Clientset.CoreV1().Pods(namespace).GetLogs(name, opts)
}

// separator for locating the start of the next log message. Sometimes
// logs may span multiple lines, locate the timestamp, log level and
// msg that always start a new log message
var logSplitter = regexp.MustCompile(`\r?\n[^ ]+ level=[[:alpha:]]+ msg=`)

func (c *Client) CiliumLogs(ctx context.Context, namespace, pod string, since time.Time, filter *regexp.Regexp) (string, error) {
	opts := &corev1.PodLogOptions{
		Container:  defaults.AgentContainerName,
		Timestamps: true,
		SinceTime:  &metav1.Time{Time: since},
	}
	req := c.PodLogs(namespace, pod, opts)
	podLogs, err := req.Stream(ctx)
	if err != nil {
		return "", fmt.Errorf("error getting cilium-agent logs for %s/%s: %w", namespace, pod, err)
	}
	defer podLogs.Close()

	buf := new(bytes.Buffer)
	scanner := bufio.NewScanner(podLogs)
	scanner.Split(func(data []byte, atEOF bool) (advance int, token []byte, err error) {
		if atEOF && len(data) == 0 {
			return 0, nil, nil
		}
		// find the full log line separator
		loc := logSplitter.FindIndex(data)
		if loc != nil {
			// Locate '\n', advance just past it
			nl := loc[0] + bytes.IndexByte(data[loc[0]:loc[1]], '\n') + 1
			return nl, data[:nl], nil
		} else if atEOF {
			// EOF, return all we have
			return len(data), data, nil
		}
		// Nothing to return
		return 0, nil, nil
	})

	for scanner.Scan() {
		if filter != nil && !filter.Match(scanner.Bytes()) {
			continue
		}
		buf.Write(scanner.Bytes())
	}
	err = scanner.Err()
	if err != nil {
		err = fmt.Errorf("error reading cilium-agent logs for %s/%s: %w", namespace, pod, err)
	}
	return buf.String(), err
}

func (c *Client) ListServices(ctx context.Context, namespace string, options metav1.ListOptions) (*corev1.ServiceList, error) {
	return c.Clientset.CoreV1().Services(namespace).List(ctx, options)
}

func (c *Client) ExecInPodWithStderr(ctx context.Context, namespace, pod, container string, command []string) (bytes.Buffer, bytes.Buffer, error) {
	result, err := c.execInPod(ctx, ExecParameters{
		Namespace: namespace,
		Pod:       pod,
		Container: container,
		Command:   command,
	})
	return result.Stdout, result.Stderr, err
}

func (c *Client) ExecInPod(ctx context.Context, namespace, pod, container string, command []string) (bytes.Buffer, error) {
	result, err := c.execInPod(ctx, ExecParameters{
		Namespace: namespace,
		Pod:       pod,
		Container: container,
		Command:   command,
	})
	if err != nil {
		return result.Stdout, err
	}

	if errString := result.Stderr.String(); errString != "" {
		return result.Stdout, fmt.Errorf("command failed (pod=%s/%s, container=%s): %q", namespace, pod, container, errString)
	}

	return result.Stdout, nil
}

func (c *Client) ExecInPodWithWriters(connCtx, killCmdCtx context.Context, namespace, pod, container string, command []string, stdout, stderr io.Writer) error {
	execParams := ExecParameters{
		Namespace: namespace,
		Pod:       pod,
		Container: container,
		Command:   command,
	}
	if killCmdCtx != nil {
		execParams.TTY = true
	}
	err := c.execInPodWithWriters(connCtx, killCmdCtx, execParams, stdout, stderr)
	if err != nil {
		return err
	}

	return nil
}

func (c *Client) CiliumStatus(ctx context.Context, namespace, pod string) (*models.StatusResponse, error) {
	stdout, err := c.ExecInPod(ctx, namespace, pod, defaults.AgentContainerName, []string{"cilium", "status", "-o", "json"})
	if err != nil {
		return nil, err
	}

	statusResponse := models.StatusResponse{}

	if err := json.Unmarshal(stdout.Bytes(), &statusResponse); err != nil {
		return nil, fmt.Errorf("unable to unmarshal response of cilium status: %w", err)
	}

	return &statusResponse, nil
}

func (c *Client) CiliumDbgEndpoints(ctx context.Context, namespace, pod string) ([]*models.Endpoint, error) {
	stdout, err := c.ExecInPod(ctx, namespace, pod, defaults.AgentContainerName, []string{"cilium", "endpoint", "list", "-o", "json"})
	if err != nil {
		return nil, err
	}

	var response []*models.Endpoint
	if err := json.Unmarshal(stdout.Bytes(), &response); err != nil {
		return nil, fmt.Errorf("unable to unmarshal response: %w", err)
	}
	return response, nil
}

func (c *Client) CreateConfigMap(ctx context.Context, namespace string, config *corev1.ConfigMap, opts metav1.CreateOptions) (*corev1.ConfigMap, error) {
	return c.Clientset.CoreV1().ConfigMaps(namespace).Create(ctx, config, opts)
}

func (c *Client) DeleteConfigMap(ctx context.Context, namespace, name string, opts metav1.DeleteOptions) error {
	return c.Clientset.CoreV1().ConfigMaps(namespace).Delete(ctx, name, opts)
}

func (c *Client) CreateDaemonSet(ctx context.Context, namespace string, ds *appsv1.DaemonSet, opts metav1.CreateOptions) (*appsv1.DaemonSet, error) {
	return c.Clientset.AppsV1().DaemonSets(namespace).Create(ctx, ds, opts)
}

func (c *Client) PatchDaemonSet(ctx context.Context, namespace, name string, pt types.PatchType, data []byte, opts metav1.PatchOptions) (*appsv1.DaemonSet, error) {
	return c.Clientset.AppsV1().DaemonSets(namespace).Patch(ctx, name, pt, data, opts)
}

func (c *Client) GetDaemonSet(ctx context.Context, namespace, name string, opts metav1.GetOptions) (*appsv1.DaemonSet, error) {
	return c.Clientset.AppsV1().DaemonSets(namespace).Get(ctx, name, opts)
}

func (c *Client) ListDaemonSet(ctx context.Context, namespace string, o metav1.ListOptions) (*appsv1.DaemonSetList, error) {
	return c.Clientset.AppsV1().DaemonSets(namespace).List(ctx, o)
}

func (c *Client) CheckDaemonSetStatus(ctx context.Context, namespace, deployment string) error {
	d, err := c.GetDaemonSet(ctx, namespace, deployment, metav1.GetOptions{})
	if err != nil {
		return err
	}

	if d == nil {
		return fmt.Errorf("deployment is not available")
	}

	if d.Status.ObservedGeneration != d.Generation {
		return fmt.Errorf("observed generation (%d) is older than generation of the desired state (%d)",
			d.Status.ObservedGeneration, d.Generation)
	}

	if d.Status.CurrentNumberScheduled != d.Status.DesiredNumberScheduled {
		return fmt.Errorf("only %d of %d replicas are scheduled", d.Status.CurrentNumberScheduled, d.Status.DesiredNumberScheduled)
	}

	if d.Status.NumberReady != d.Status.DesiredNumberScheduled {
		return fmt.Errorf("only %d of %d replicas are ready", d.Status.NumberReady, d.Status.DesiredNumberScheduled)
	}

	if d.Status.UpdatedNumberScheduled != d.Status.DesiredNumberScheduled {
		return fmt.Errorf("only %d of %d replicas are up-to-date", d.Status.UpdatedNumberScheduled, d.Status.DesiredNumberScheduled)
	}

	return nil
}

func (c *Client) GetStatefulSet(ctx context.Context, namespace, name string, opts metav1.GetOptions) (*appsv1.StatefulSet, error) {
	return c.Clientset.AppsV1().StatefulSets(namespace).Get(ctx, name, opts)
}

func (c *Client) GetCRD(ctx context.Context, name string, opts metav1.GetOptions) (*apiextensions.CustomResourceDefinition, error) {
	return c.ExtensionClientset.ApiextensionsV1().CustomResourceDefinitions().Get(ctx, name, opts)
}

// Kubernetes Network Policies specific commands

func (c *Client) DeleteKubernetesNetworkPolicy(ctx context.Context, namespace, name string, opts metav1.DeleteOptions) error {
	return c.Clientset.NetworkingV1().NetworkPolicies(namespace).Delete(ctx, name, opts)
}

type Kind int

const (
	KindUnknown Kind = iota
	KindMinikube
	KindKind
	KindEKS
	KindGKE
	KindAKS
	KindMicrok8s
	KindRancherDesktop
	KindK3s
)

func (k Kind) String() string {
	switch k {
	case KindUnknown:
		return "unknown"
	case KindMinikube:
		return "minikube"
	case KindKind:
		return "kind"
	case KindEKS:
		return "EKS"
	case KindGKE:
		return "GKE"
	case KindAKS:
		return "AKS"
	case KindMicrok8s:
		return "microk8s"
	case KindRancherDesktop:
		return "rancher-desktop"
	case KindK3s:
		return "K3s"
	default:
		return "invalid"
	}
}

type Flavor struct {
	ClusterName string
	Kind        Kind
}

type Platform struct {
	OS   string
	Arch string
}

func (c *Client) AutodetectFlavor(ctx context.Context) Flavor {
	f := Flavor{
		ClusterName: c.ClusterName(),
	}

	if c.ClusterName() == "minikube" || c.ContextName() == "minikube" {
		f.Kind = KindMinikube
		return f
	}

	if strings.HasPrefix(c.ClusterName(), "microk8s-") || c.ContextName() == "microk8s" {
		f.Kind = KindMicrok8s
	}

	if c.ClusterName() == "rancher-desktop" || c.ContextName() == "rancher-desktop" {
		f.Kind = KindRancherDesktop
		return f
	}

	// When creating a cluster with kind create cluster --name foo,
	// the context and cluster name are kind-foo.
	if strings.HasPrefix(c.ClusterName(), "kind-") || strings.HasPrefix(c.ContextName(), "kind-") {
		f.Kind = KindKind
		return f
	}

	if strings.HasPrefix(c.ClusterName(), "gke_") {
		f.Kind = KindGKE
		return f
	}

	// When creating a cluster with eksctl create cluster --name foo,
	// the cluster name is foo.<region>.eksctl.io
	if strings.HasSuffix(c.ClusterName(), ".eksctl.io") {
		f.ClusterName = strings.ReplaceAll(c.ClusterName(), ".", "-")
		f.Kind = KindEKS
		return f
	}

	if context, ok := c.RawConfig.Contexts[c.ContextName()]; ok {
		if cluster, ok := c.RawConfig.Clusters[context.Cluster]; ok {
			if strings.HasSuffix(cluster.Server, "eks.amazonaws.com") {
				f.Kind = KindEKS
				return f
			} else if strings.HasSuffix(cluster.Server, "azmk8s.io:443") {
				f.Kind = KindAKS
				return f
			}
		}
	}

	nodeList, err := c.ListNodes(ctx, metav1.ListOptions{})
	if err != nil {
		return f
	}
	// Assume k3s if the k8s master node runs k3s
	for _, node := range nodeList.Items {
		isMaster := node.Labels["node-role.kubernetes.io/master"]
		if isMaster != "true" {
			continue
		}
		instanceType, ok := node.Labels[corev1.LabelInstanceTypeStable]
		if !ok {
			instanceType = node.Labels[corev1.LabelInstanceType]
		}
		if instanceType == "k3s" {
			f.Kind = KindK3s
			return f
		}
	}

	return f
}

func (c *Client) ListCiliumEndpoints(ctx context.Context, namespace string, options metav1.ListOptions) (*ciliumv2.CiliumEndpointList, error) {
	return c.CiliumClientset.CiliumV2().CiliumEndpoints(namespace).List(ctx, options)
}

func (c *Client) ListCiliumEndpointSlices(ctx context.Context, options metav1.ListOptions) (*ciliumv2alpha1.CiliumEndpointSliceList, error) {
	return c.CiliumClientset.CiliumV2alpha1().CiliumEndpointSlices().List(ctx, options)
}

func (c *Client) ListCiliumEnvoyConfigs(ctx context.Context, namespace string, options metav1.ListOptions) (*ciliumv2.CiliumEnvoyConfigList, error) {
	return c.CiliumClientset.CiliumV2().CiliumEnvoyConfigs(namespace).List(ctx, options)
}

func (c *Client) GetNode(ctx context.Context, name string, opts metav1.GetOptions) (*corev1.Node, error) {
	return c.Clientset.CoreV1().Nodes().Get(ctx, name, opts)
}

func (c *Client) ListNodes(ctx context.Context, options metav1.ListOptions) (*corev1.NodeList, error) {
	return c.Clientset.CoreV1().Nodes().List(ctx, options)
}

func (c *Client) PatchNode(ctx context.Context, nodeName string, pt types.PatchType, data []byte) (*corev1.Node, error) {
	return c.Clientset.CoreV1().Nodes().Patch(ctx, nodeName, pt, data, metav1.PatchOptions{})
}

func (c *Client) ListCiliumExternalWorkloads(ctx context.Context, opts metav1.ListOptions) (*ciliumv2.CiliumExternalWorkloadList, error) {
	return c.CiliumClientset.CiliumV2().CiliumExternalWorkloads().List(ctx, opts)
}

func (c *Client) GetCiliumExternalWorkload(ctx context.Context, name string, opts metav1.GetOptions) (*ciliumv2.CiliumExternalWorkload, error) {
	return c.CiliumClientset.CiliumV2().CiliumExternalWorkloads().Get(ctx, name, opts)
}

func (c *Client) CreateCiliumExternalWorkload(ctx context.Context, cew *ciliumv2.CiliumExternalWorkload, opts metav1.CreateOptions) (*ciliumv2.CiliumExternalWorkload, error) {
	return c.CiliumClientset.CiliumV2().CiliumExternalWorkloads().Create(ctx, cew, opts)
}

func (c *Client) DeleteCiliumExternalWorkload(ctx context.Context, name string, opts metav1.DeleteOptions) error {
	return c.CiliumClientset.CiliumV2().CiliumExternalWorkloads().Delete(ctx, name, opts)
}

func (c *Client) ListCiliumNetworkPolicies(ctx context.Context, namespace string, opts metav1.ListOptions) (*ciliumv2.CiliumNetworkPolicyList, error) {
	return c.CiliumClientset.CiliumV2().CiliumNetworkPolicies(namespace).List(ctx, opts)
}

func (c *Client) DeleteCiliumNetworkPolicy(ctx context.Context, namespace, name string, opts metav1.DeleteOptions) error {
	return c.CiliumClientset.CiliumV2().CiliumNetworkPolicies(namespace).Delete(ctx, name, opts)
}

func (c *Client) ListCiliumEgressGatewayPolicies(ctx context.Context, opts metav1.ListOptions) (*ciliumv2.CiliumEgressGatewayPolicyList, error) {
	return c.CiliumClientset.CiliumV2().CiliumEgressGatewayPolicies().List(ctx, opts)
}

func (c *Client) DeleteCiliumEgressGatewayPolicy(ctx context.Context, name string, opts metav1.DeleteOptions) error {
	return c.CiliumClientset.CiliumV2().CiliumEgressGatewayPolicies().Delete(ctx, name, opts)
}

func (c *Client) ListCiliumBGPPeeringPolicies(ctx context.Context, opts metav1.ListOptions) (*ciliumv2alpha1.CiliumBGPPeeringPolicyList, error) {
	return c.CiliumClientset.CiliumV2alpha1().CiliumBGPPeeringPolicies().List(ctx, opts)
}

func (c *Client) ListCiliumCIDRGroups(ctx context.Context, opts metav1.ListOptions) (*ciliumv2alpha1.CiliumCIDRGroupList, error) {
	return c.CiliumClientset.CiliumV2alpha1().CiliumCIDRGroups().List(ctx, opts)
}

func (c *Client) ListCiliumClusterwideNetworkPolicies(ctx context.Context, opts metav1.ListOptions) (*ciliumv2.CiliumClusterwideNetworkPolicyList, error) {
	return c.CiliumClientset.CiliumV2().CiliumClusterwideNetworkPolicies().List(ctx, opts)
}

func (c *Client) ListCiliumClusterwideEnvoyConfigs(ctx context.Context, opts metav1.ListOptions) (*ciliumv2.CiliumClusterwideEnvoyConfigList, error) {
	return c.CiliumClientset.CiliumV2().CiliumClusterwideEnvoyConfigs().List(ctx, opts)
}

func (c *Client) DeleteCiliumClusterwideNetworkPolicy(ctx context.Context, name string, opts metav1.DeleteOptions) error {
	return c.CiliumClientset.CiliumV2().CiliumClusterwideNetworkPolicies().Delete(ctx, name, opts)
}

func (c *Client) GetVersion(_ context.Context) (string, error) {
	v, err := c.Clientset.Discovery().ServerVersion()
	if err != nil {
		return "", fmt.Errorf("failed to get Kubernetes version: %w", err)
	}
	return fmt.Sprintf("%#v", *v), nil
}

func (c *Client) ListEvents(ctx context.Context, o metav1.ListOptions) (*corev1.EventList, error) {
	return c.Clientset.CoreV1().Events(corev1.NamespaceAll).List(ctx, o)
}

func (c *Client) ListNamespaces(ctx context.Context, o metav1.ListOptions) (*corev1.NamespaceList, error) {
	return c.Clientset.CoreV1().Namespaces().List(ctx, o)
}

func (c *Client) GetPodsTable(_ context.Context) (*metav1.Table, error) {
	r := resource.NewBuilder(c.RESTClientGetter).
		Unstructured().
		AllNamespaces(true).
		ResourceTypes("pods").
		SingleResourceType().
		SelectAllParam(true).
		RequestChunksOf(500).
		ContinueOnError().
		Latest().
		Flatten().
		TransformRequests(func(r *rest.Request) {
			r.SetHeader(
				"Accept", fmt.Sprintf("application/json;as=Table;v=%s;g=%s", metav1.SchemeGroupVersion.Version, metav1.GroupName),
			)
		}).
		Do()
	if r.Err() != nil {
		return nil, r.Err()
	}
	infos, err := r.Infos()
	if err != nil {
		return nil, err
	}
	objects := make([]runtime.Object, 0, len(infos))
	for _, info := range infos {
		objects = append(objects, info.Object)
	}
	return unstructuredSliceToTable(objects)
}

func (c *Client) ProxyGet(ctx context.Context, namespace, name, url string) (string, error) {
	res := c.Clientset.CoreV1().RESTClient().Get().
		Namespace(namespace).
		Resource("pods").
		Name(name).
		SubResource("proxy").
		Suffix(url).
		Do(ctx)

	rawbody, err := res.Raw()
	if err != nil {
		return "", err
	}
	return string(rawbody), nil
}

func (c *Client) ListUnstructured(ctx context.Context, gvr schema.GroupVersionResource, namespace *string, o metav1.ListOptions) (*unstructured.UnstructuredList, error) {
	if namespace == nil {
		return c.DynamicClientset.Resource(gvr).List(ctx, o)
	}
	return c.DynamicClientset.Resource(gvr).Namespace(*namespace).List(ctx, o)
}

func (c *Client) ListEndpoints(ctx context.Context, o metav1.ListOptions) (*corev1.EndpointsList, error) {
	return c.Clientset.CoreV1().Endpoints(corev1.NamespaceAll).List(ctx, o)
}

func (c *Client) ListIngressClasses(ctx context.Context, o metav1.ListOptions) (*networkingv1.IngressClassList, error) {
	return c.Clientset.NetworkingV1().IngressClasses().List(ctx, o)
}

func (c *Client) ListIngresses(ctx context.Context, o metav1.ListOptions) (*networkingv1.IngressList, error) {
	return c.Clientset.NetworkingV1().Ingresses(corev1.NamespaceAll).List(ctx, o)
}

func (c *Client) ListNetworkPolicies(ctx context.Context, o metav1.ListOptions) (*networkingv1.NetworkPolicyList, error) {
	return c.Clientset.NetworkingV1().NetworkPolicies(corev1.NamespaceAll).List(ctx, o)
}

func (c *Client) ListCiliumIdentities(ctx context.Context) (*ciliumv2.CiliumIdentityList, error) {
	return c.CiliumClientset.CiliumV2().CiliumIdentities().List(ctx, metav1.ListOptions{})
}

func (c *Client) ListCiliumNodes(ctx context.Context) (*ciliumv2.CiliumNodeList, error) {
	return c.CiliumClientset.CiliumV2().CiliumNodes().List(ctx, metav1.ListOptions{})
}

func (c *Client) ListCiliumNodeConfigs(ctx context.Context, namespace string, opts metav1.ListOptions) (*ciliumv2alpha1.CiliumNodeConfigList, error) {
	return c.CiliumClientset.CiliumV2alpha1().CiliumNodeConfigs(namespace).List(ctx, opts)
}

func (c *Client) ListCiliumPodIPPools(ctx context.Context, opts metav1.ListOptions) (*ciliumv2alpha1.CiliumPodIPPoolList, error) {
	return c.CiliumClientset.CiliumV2alpha1().CiliumPodIPPools().List(ctx, opts)
}

func (c *Client) GetLogs(ctx context.Context, namespace, name, container string, opts corev1.PodLogOptions) (string, error) {
	opts.Container = container
	r := c.Clientset.CoreV1().Pods(namespace).GetLogs(name, &opts)
	s, err := r.Stream(ctx)
	if err != nil {
		return "", err
	}
	defer s.Close()
	var b bytes.Buffer
	if _, err = io.Copy(&b, s); err != nil {
		return "", err
	}
	return b.String(), nil
}

// GetCiliumVersion returns a semver.Version representing the version of cilium
// running in the cilium-agent pod
func (c *Client) GetCiliumVersion(ctx context.Context, p *corev1.Pod) (*semver.Version, error) {
	o, _, err := c.ExecInPodWithStderr(
		ctx,
		p.Namespace,
		p.Name,
		defaults.AgentContainerName,
		[]string{"cilium", "version", "-o", "jsonpath={$.Daemon.Version}"},
	)
	if err != nil {
		return nil, fmt.Errorf("unable to fetch cilium version on pod %q: %w", p.Name, err)
	}

	v, _, _ := strings.Cut(strings.TrimSpace(o.String()), "-") // strips proprietary -releaseX suffix
	podVersion, err := semver.Parse(v)
	if err != nil {
		return nil, fmt.Errorf("unable to parse cilium version on pod %q: %w", p.Name, err)
	}

	return &podVersion, nil
}

func (c *Client) GetRunningCiliumVersion(ciliumHelmReleaseName string) (string, error) {
	release, err := action.NewGet(c.HelmActionConfig).Run(ciliumHelmReleaseName)
	if err != nil {
		return "", err
	}
	return release.Chart.Metadata.Version, nil
}

func (c *Client) ListCiliumLoadBalancerIPPools(ctx context.Context, opts metav1.ListOptions) (*ciliumv2alpha1.CiliumLoadBalancerIPPoolList, error) {
	return c.CiliumClientset.CiliumV2alpha1().CiliumLoadBalancerIPPools().List(ctx, opts)
}

func (c *Client) ListCiliumLocalRedirectPolicies(ctx context.Context, namespace string, opts metav1.ListOptions) (*ciliumv2.CiliumLocalRedirectPolicyList, error) {
	return c.CiliumClientset.CiliumV2().CiliumLocalRedirectPolicies(namespace).List(ctx, opts)
}

func (c *Client) GetServerVersion() (*semver.Version, error) {
	sv, err := c.Clientset.Discovery().ServerVersion()
	if err != nil {
		return nil, err
	}

	var ver semver.Version
	// Try GitVersion first. In case of error fallback to MajorMinor
	if sv.GitVersion != "" {
		// This is a string like "v1.9.0"
		ver, err = versioncheck.Version(sv.GitVersion)
		if err == nil {
			return &ver, nil
		}
	}

	if sv.Major != "" && sv.Minor != "" {
		ver, err = versioncheck.Version(fmt.Sprintf("%s.%s", sv.Major, sv.Minor))
		if err == nil {
			return &ver, nil
		}
	}
	return nil, fmt.Errorf("unable to parse Kubernetes version (got %s): %s", sv.String(), err)
}

func (c *Client) GetIngress(ctx context.Context, namespace string, name string, opts metav1.GetOptions) (*networkingv1.Ingress, error) {
	return c.Clientset.NetworkingV1().Ingresses(namespace).Get(ctx, name, opts)
}

func (c *Client) CreateIngress(ctx context.Context, namespace string, ingress *networkingv1.Ingress, opts metav1.CreateOptions) (*networkingv1.Ingress, error) {
	return c.Clientset.NetworkingV1().Ingresses(namespace).Create(ctx, ingress, opts)
}

// GetHelmValues is the function for cilium cli sysdump to collect the helm values from the release directly
func (c *Client) GetHelmValues(_ context.Context, releaseName string, namespace string) (string, error) {
	if c.RESTClientGetter == nil {
		return "", fmt.Errorf("no RESTClientGetter for Helm Values")
	}
	helmDriver := ""
	actionConfig := action.Configuration{}
	logger := func(_ string, _ ...interface{}) {}
	if err := actionConfig.Init(c.RESTClientGetter, namespace, helmDriver, logger); err != nil {
		return "", err
	}
	helmGetValsClient := action.NewGetValues(&actionConfig)
	vals, err := helmGetValsClient.Run(releaseName)
	if err != nil {
		return "", fmt.Errorf("unable to retrieve helm value from release %s: %w", releaseName, err)
	}

	valuesBuf := new(bytes.Buffer)
	if err = output.EncodeYAML(valuesBuf, vals); err != nil {
		return "", fmt.Errorf("unable to parse helm values from release %s: %w", releaseName, err)
	}
	return valuesBuf.String(), nil

}

// GetHelmMetadata is the function for cilium cli sysdump to collect the helm metadata from the release directly
func (c *Client) GetHelmMetadata(_ context.Context, releaseName string, namespace string) (string, error) {
	if c.RESTClientGetter == nil {
		return "", fmt.Errorf("no RESTClientGetter for Helm Values")
	}
	helmDriver := ""
	actionConfig := action.Configuration{}
	logger := func(_ string, _ ...interface{}) {}
	if err := actionConfig.Init(c.RESTClientGetter, namespace, helmDriver, logger); err != nil {
		return "", err
	}

	client := action.NewGetMetadata(&actionConfig)
	meta, err := client.Run(releaseName)
	if err != nil {
		return "", fmt.Errorf("unable to retrieve helm meta from release %s: %w", releaseName, err)
	}

	buf := new(bytes.Buffer)
	if err = output.EncodeYAML(buf, meta); err != nil {
		return "", fmt.Errorf("unable to parse helm metas from release %s: %w", releaseName, err)
	}
	return buf.String(), nil

}

// CreateEphemeralContainer will create a EphemeralContainer (debug container) in the specified pod.
// EphemeralContainers are special containers which can be added after-the-fact in running pods. They're
// useful for debugging, either when the target container image doesn't have necessary tools, or because
// the pod has no running containers due to a crash.
//
// see https://kubernetes.io/docs/concepts/workloads/pods/ephemeral-containers/
//
// EphemeralContainers were added in there current form (behind a feature gate) in 1.22. They are scheduled for GA in v1.25.
func (c *Client) CreateEphemeralContainer(ctx context.Context, pod *corev1.Pod, ec *corev1.EphemeralContainer) (*corev1.Pod, error) {
	oldJS, err := json.Marshal(pod)
	if err != nil {
		return nil, err // unlikely
	}

	newPod := pod.DeepCopy()
	newPod.Spec.EphemeralContainers = append(newPod.Spec.EphemeralContainers, *ec)

	newJS, err := json.Marshal(newPod)
	if err != nil {
		return nil, err // unlikely
	}

	patch, err := strategicpatch.CreateTwoWayMergePatch(oldJS, newJS, pod)
	if err != nil {
		return nil, fmt.Errorf("could not create patch: %w", err) // unlikely
	}

	return c.Clientset.CoreV1().Pods(pod.Namespace).Patch(
		ctx, pod.Name, types.StrategicMergePatchType, patch, metav1.PatchOptions{}, "ephemeralcontainers",
	)
}
