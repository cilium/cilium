// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package k8s

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/blang/semver/v4"
	"github.com/distribution/distribution/reference"
	"helm.sh/helm/v3/pkg/chartutil"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apiextensions "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	apiextensionsclientset "k8s.io/apiextensions-apiserver/pkg/client/clientset/clientset"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
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

	tetragonv1alpha1 "github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
	tetragonClientset "github.com/cilium/tetragon/pkg/k8s/client/clientset/versioned"

	"github.com/cilium/cilium-cli/defaults"
	"github.com/cilium/cilium-cli/internal/helm"
	"github.com/cilium/cilium-cli/internal/utils"
)

type Client struct {
	Clientset          kubernetes.Interface
	ExtensionClientset apiextensionsclientset.Interface // k8s api extension needed to retrieve CRDs
	DynamicClientset   dynamic.Interface
	CiliumClientset    ciliumClientset.Interface
	TetragonClientset  tetragonClientset.Interface
	Config             *rest.Config
	RawConfig          clientcmdapi.Config
	RESTClientGetter   genericclioptions.RESTClientGetter
	contextName        string
}

func NewClient(contextName, kubeconfig string) (*Client, error) {
	// Register the Cilium types in the default scheme.
	_ = ciliumv2.AddToScheme(scheme.Scheme)
	_ = ciliumv2alpha1.AddToScheme(scheme.Scheme)
	_ = tetragonv1alpha1.AddToScheme(scheme.Scheme)

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

	tetragonClientset, err := tetragonClientset.NewForConfig(config)
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

	return &Client{
		CiliumClientset:    ciliumClientset,
		TetragonClientset:  tetragonClientset,
		Clientset:          clientset,
		ExtensionClientset: extensionClientset,
		Config:             config,
		DynamicClientset:   dynamicClientset,
		RawConfig:          rawConfig,
		RESTClientGetter:   &restClientGetter,
		contextName:        contextName,
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

func (c *Client) CreateClusterRole(ctx context.Context, role *rbacv1.ClusterRole, opts metav1.CreateOptions) (*rbacv1.ClusterRole, error) {
	return c.Clientset.RbacV1().ClusterRoles().Create(ctx, role, opts)
}

func (c *Client) DeleteClusterRole(ctx context.Context, name string, opts metav1.DeleteOptions) error {
	return c.Clientset.RbacV1().ClusterRoles().Delete(ctx, name, opts)
}

func (c *Client) CreateClusterRoleBinding(ctx context.Context, role *rbacv1.ClusterRoleBinding, opts metav1.CreateOptions) (*rbacv1.ClusterRoleBinding, error) {
	return c.Clientset.RbacV1().ClusterRoleBindings().Create(ctx, role, opts)
}

func (c *Client) DeleteClusterRoleBinding(ctx context.Context, name string, opts metav1.DeleteOptions) error {
	return c.Clientset.RbacV1().ClusterRoleBindings().Delete(ctx, name, opts)
}

func (c *Client) CreateRole(ctx context.Context, namespace string, role *rbacv1.Role, opts metav1.CreateOptions) (*rbacv1.Role, error) {
	return c.Clientset.RbacV1().Roles(namespace).Create(ctx, role, opts)
}

func (c *Client) UpdateRole(ctx context.Context, namespace string, role *rbacv1.Role, opts metav1.UpdateOptions) (*rbacv1.Role, error) {
	return c.Clientset.RbacV1().Roles(namespace).Update(ctx, role, opts)
}

func (c *Client) DeleteRole(ctx context.Context, namespace string, name string, opts metav1.DeleteOptions) error {
	return c.Clientset.RbacV1().Roles(namespace).Delete(ctx, name, opts)
}

func (c *Client) CreateRoleBinding(ctx context.Context, namespace string, roleBinding *rbacv1.RoleBinding, opts metav1.CreateOptions) (*rbacv1.RoleBinding, error) {
	return c.Clientset.RbacV1().RoleBindings(namespace).Create(ctx, roleBinding, opts)
}

func (c *Client) UpdateRoleBinding(ctx context.Context, namespace string, roleBinding *rbacv1.RoleBinding, opts metav1.UpdateOptions) (*rbacv1.RoleBinding, error) {
	return c.Clientset.RbacV1().RoleBindings(namespace).Update(ctx, roleBinding, opts)
}

func (c *Client) DeleteRoleBinding(ctx context.Context, namespace, name string, opts metav1.DeleteOptions) error {
	return c.Clientset.RbacV1().RoleBindings(namespace).Delete(ctx, name, opts)
}

func (c *Client) GetConfigMap(ctx context.Context, namespace, name string, opts metav1.GetOptions) (*corev1.ConfigMap, error) {
	return c.Clientset.CoreV1().ConfigMaps(namespace).Get(ctx, name, opts)
}

func (c *Client) PatchConfigMap(ctx context.Context, namespace, name string, pt types.PatchType, data []byte, opts metav1.PatchOptions) (*corev1.ConfigMap, error) {
	return c.Clientset.CoreV1().ConfigMaps(namespace).Patch(ctx, name, pt, data, opts)
}

func (c *Client) UpdateConfigMap(ctx context.Context, configMap *corev1.ConfigMap, opts metav1.UpdateOptions) (*corev1.ConfigMap, error) {
	return c.Clientset.CoreV1().ConfigMaps(configMap.Namespace).Update(ctx, configMap, opts)
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

func (c *Client) CreateEndpoints(ctx context.Context, namespace string, ep *corev1.Endpoints, opts metav1.CreateOptions) (*corev1.Endpoints, error) {
	return c.Clientset.CoreV1().Endpoints(namespace).Create(ctx, ep, opts)
}

func (c *Client) GetEndpoints(ctx context.Context, namespace, name string, opts metav1.GetOptions) (*corev1.Endpoints, error) {
	return c.Clientset.CoreV1().Endpoints(namespace).Get(ctx, name, opts)
}

func (c *Client) DeleteEndpoints(ctx context.Context, namespace, name string, opts metav1.DeleteOptions) error {
	return c.Clientset.CoreV1().Endpoints(namespace).Delete(ctx, name, opts)
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

func (c *Client) PatchDeployment(ctx context.Context, namespace, name string, pt types.PatchType, data []byte, opts metav1.PatchOptions) (*appsv1.Deployment, error) {
	return c.Clientset.AppsV1().Deployments(namespace).Patch(ctx, name, pt, data, opts)
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

func (c *Client) CreateNamespace(ctx context.Context, namespace string, opts metav1.CreateOptions) (*corev1.Namespace, error) {
	return c.Clientset.CoreV1().Namespaces().Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: namespace}}, opts)
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
		} else {
			// Nothing to return
			return 0, nil, nil
		}
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

func (c *Client) WriteFileToPod(ctx context.Context, namespace, pod, container, path string, content []byte, mode int32) error {
	result, err := c.execInPod(ctx, ExecParameters{
		Namespace: namespace,
		Pod:       pod,
		Container: container,
	})
	if err != nil {
		return fmt.Errorf("error executing cat in pod: %s", err)
	}

	if errString := result.Stderr.String(); errString != "" {
		return fmt.Errorf("error writing file to pod: %s", errString)
	}

	return nil
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
		return bytes.Buffer{}, err
	}

	if errString := result.Stderr.String(); errString != "" {
		return bytes.Buffer{}, fmt.Errorf("command failed: %s", errString)
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

func (c *Client) DeleteDaemonSet(ctx context.Context, namespace, name string, opts metav1.DeleteOptions) error {
	return c.Clientset.AppsV1().DaemonSets(namespace).Delete(ctx, name, opts)
}

func (c *Client) GetCRD(ctx context.Context, name string, opts metav1.GetOptions) (*apiextensions.CustomResourceDefinition, error) {
	return c.ExtensionClientset.ApiextensionsV1().CustomResourceDefinitions().Get(ctx, name, opts)
}

// Kubernetes Network Policies specific commands

func (c *Client) ListKubernetesNetworkPolicies(ctx context.Context, namespace string, opts metav1.ListOptions) (*networkingv1.NetworkPolicyList, error) {
	return c.Clientset.NetworkingV1().NetworkPolicies(namespace).List(ctx, opts)
}

func (c *Client) GetKubernetesNetworkPolicy(ctx context.Context, namespace, name string, opts metav1.GetOptions) (*networkingv1.NetworkPolicy, error) {
	return c.Clientset.NetworkingV1().NetworkPolicies(namespace).Get(ctx, name, opts)
}

func (c *Client) CreateKubernetesNetworkPolicy(ctx context.Context, policy *networkingv1.NetworkPolicy, opts metav1.CreateOptions) (*networkingv1.NetworkPolicy, error) {
	return c.Clientset.NetworkingV1().NetworkPolicies(policy.Namespace).Create(ctx, policy, opts)
}

func (c *Client) UpdateKubernetesNetworkPolicy(ctx context.Context, policy *networkingv1.NetworkPolicy, opts metav1.UpdateOptions) (*networkingv1.NetworkPolicy, error) {
	return c.Clientset.NetworkingV1().NetworkPolicies(policy.Namespace).Update(ctx, policy, opts)
}

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

func (c *Client) CreateResourceQuota(ctx context.Context, namespace string, rq *corev1.ResourceQuota, opts metav1.CreateOptions) (*corev1.ResourceQuota, error) {
	return c.Clientset.CoreV1().ResourceQuotas(namespace).Create(ctx, rq, opts)
}

func (c *Client) DeleteResourceQuota(ctx context.Context, namespace, name string, opts metav1.DeleteOptions) error {
	return c.Clientset.CoreV1().ResourceQuotas(namespace).Delete(ctx, name, opts)
}

func (c *Client) GetCiliumEndpoint(ctx context.Context, namespace, name string, opts metav1.GetOptions) (*ciliumv2.CiliumEndpoint, error) {
	return c.CiliumClientset.CiliumV2().CiliumEndpoints(namespace).Get(ctx, name, opts)
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

func (c *Client) GetCiliumNetworkPolicy(ctx context.Context, namespace, name string, opts metav1.GetOptions) (*ciliumv2.CiliumNetworkPolicy, error) {
	return c.CiliumClientset.CiliumV2().CiliumNetworkPolicies(namespace).Get(ctx, name, opts)
}

func (c *Client) CreateCiliumNetworkPolicy(ctx context.Context, cnp *ciliumv2.CiliumNetworkPolicy, opts metav1.CreateOptions) (*ciliumv2.CiliumNetworkPolicy, error) {
	return c.CiliumClientset.CiliumV2().CiliumNetworkPolicies(cnp.Namespace).Create(ctx, cnp, opts)
}

func (c *Client) UpdateCiliumNetworkPolicy(ctx context.Context, cnp *ciliumv2.CiliumNetworkPolicy, opts metav1.UpdateOptions) (*ciliumv2.CiliumNetworkPolicy, error) {
	return c.CiliumClientset.CiliumV2().CiliumNetworkPolicies(cnp.Namespace).Update(ctx, cnp, opts)
}

func (c *Client) DeleteCiliumNetworkPolicy(ctx context.Context, namespace, name string, opts metav1.DeleteOptions) error {
	return c.CiliumClientset.CiliumV2().CiliumNetworkPolicies(namespace).Delete(ctx, name, opts)
}

func (c *Client) ListCiliumBGPPeeringPolicies(ctx context.Context, opts metav1.ListOptions) (*ciliumv2alpha1.CiliumBGPPeeringPolicyList, error) {
	return c.CiliumClientset.CiliumV2alpha1().CiliumBGPPeeringPolicies().List(ctx, opts)
}

func (c *Client) ListCiliumClusterwideNetworkPolicies(ctx context.Context, opts metav1.ListOptions) (*ciliumv2.CiliumClusterwideNetworkPolicyList, error) {
	return c.CiliumClientset.CiliumV2().CiliumClusterwideNetworkPolicies().List(ctx, opts)
}

func (c *Client) ListCiliumClusterwideEnvoyConfigs(ctx context.Context, opts metav1.ListOptions) (*ciliumv2.CiliumClusterwideEnvoyConfigList, error) {
	return c.CiliumClientset.CiliumV2().CiliumClusterwideEnvoyConfigs().List(ctx, opts)
}

func (c *Client) GetCiliumClusterwideNetworkPolicy(ctx context.Context, name string, opts metav1.GetOptions) (*ciliumv2.CiliumClusterwideNetworkPolicy, error) {
	return c.CiliumClientset.CiliumV2().CiliumClusterwideNetworkPolicies().Get(ctx, name, opts)
}

func (c *Client) CreateCiliumClusterwideNetworkPolicy(ctx context.Context, ccnp *ciliumv2.CiliumClusterwideNetworkPolicy, opts metav1.CreateOptions) (*ciliumv2.CiliumClusterwideNetworkPolicy, error) {
	return c.CiliumClientset.CiliumV2().CiliumClusterwideNetworkPolicies().Create(ctx, ccnp, opts)
}

func (c *Client) UpdateCiliumClusterwideNetworkPolicy(ctx context.Context, ccnp *ciliumv2.CiliumClusterwideNetworkPolicy, opts metav1.UpdateOptions) (*ciliumv2.CiliumClusterwideNetworkPolicy, error) {
	return c.CiliumClientset.CiliumV2().CiliumClusterwideNetworkPolicies().Update(ctx, ccnp, opts)
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

func (c *Client) GetPodsTable(ctx context.Context) (*metav1.Table, error) {
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
	i, err := r.Infos()
	if err != nil {
		return nil, err
	}
	if len(i) != 1 {
		return nil, fmt.Errorf("expected a single kind of resource (got %d)", len(i))
	}
	return unstructuredToTable(i[0].Object)
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

func (c *Client) GetLogs(ctx context.Context, namespace, name, container string, sinceTime time.Time, limitBytes int64, previous bool) (string, error) {
	t := metav1.NewTime(sinceTime)
	o := corev1.PodLogOptions{
		Container:  container,
		Follow:     false,
		LimitBytes: &limitBytes,
		Previous:   previous,
		SinceTime:  &t,
		Timestamps: true,
	}
	r := c.Clientset.CoreV1().Pods(namespace).GetLogs(name, &o)
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

func getCiliumVersionFromImage(image string) (string, error) {
	// default to "latest" as k8s may not include it explicitly
	version := "latest"

	ref, err := reference.Parse(image)
	if err != nil {
		// Image has an invalid name, skip it
		return "", err
	}

	tagged, isTagged := ref.(reference.Tagged)
	if isTagged {
		version = tagged.Tag()
	}

	named, isNamed := ref.(reference.Named)
	if isNamed {
		path := reference.Path(named)
		strs := strings.Split(path, "/")

		// Take the last element as an image name
		imageName := strs[len(strs)-1]
		if !strings.HasPrefix(imageName, "cilium") {
			// Not likely to be Cilium
			return "", fmt.Errorf("image name %s is not prefixed with cilium", imageName)
		}

		// Add any part in the pod image separated by a '-` to the version,
		// e.g., "quay.io/cilium/cilium-ci:1234" -> "-ci:1234"
		dash := strings.Index(imageName, "-")
		if dash >= 0 {
			version = imageName[dash:] + ":" + version
		}
	} else {
		// Image somehow doesn't contain name, skip it.
		return "", fmt.Errorf("image does't contain name")
	}

	return version, nil
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

func (c *Client) GetRunningCiliumVersion(ctx context.Context, namespace string) (string, error) {
	pods, err := c.ListPods(ctx, namespace, metav1.ListOptions{LabelSelector: defaults.AgentPodSelector})
	if err != nil {
		return "", fmt.Errorf("unable to list cilium pods: %w", err)
	}
	if len(pods.Items) > 0 && len(pods.Items[0].Spec.Containers) > 0 {
		for _, container := range pods.Items[0].Spec.Containers {
			version, err := getCiliumVersionFromImage(container.Image)
			if err != nil {
				continue
			}
			return version, nil
		}
		return "", errors.New("unable to obtain cilium version: no cilium container found")
	}
	return "", errors.New("unable to obtain cilium version: no cilium pods found")
}

func (c *Client) ListCiliumEgressGatewayPolicies(ctx context.Context, opts metav1.ListOptions) (*ciliumv2.CiliumEgressGatewayPolicyList, error) {
	return c.CiliumClientset.CiliumV2().CiliumEgressGatewayPolicies().List(ctx, opts)
}

func (c *Client) ListCiliumLoadBalancerIPPools(ctx context.Context, opts metav1.ListOptions) (*ciliumv2alpha1.CiliumLoadBalancerIPPoolList, error) {
	return c.CiliumClientset.CiliumV2alpha1().CiliumLoadBalancerIPPools().List(ctx, opts)
}

func (c *Client) ListCiliumLocalRedirectPolicies(ctx context.Context, namespace string, opts metav1.ListOptions) (*ciliumv2.CiliumLocalRedirectPolicyList, error) {
	return c.CiliumClientset.CiliumV2().CiliumLocalRedirectPolicies(namespace).List(ctx, opts)
}

func (c *Client) GetPlatform(ctx context.Context) (*Platform, error) {
	v, err := c.Clientset.Discovery().ServerVersion()
	if err != nil {
		return nil, fmt.Errorf("failed to get Kubernetes version: %w", err)
	}
	fileds := strings.Split(v.Platform, "/")
	if len(fileds) != 2 {
		return nil, fmt.Errorf("unknown platform type")
	}
	return &Platform{
		OS:   fileds[0],
		Arch: fileds[1],
	}, err
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

func (c *Client) CreateIngressClass(ctx context.Context, ingressClass *networkingv1.IngressClass, opts metav1.CreateOptions) (*networkingv1.IngressClass, error) {
	return c.Clientset.NetworkingV1().IngressClasses().Create(ctx, ingressClass, opts)
}

func (c *Client) DeleteIngressClass(ctx context.Context, name string, opts metav1.DeleteOptions) error {
	return c.Clientset.NetworkingV1().IngressClasses().Delete(ctx, name, opts)
}

// GetHelmState is a wrapper function that gets cilium-cli-helm-values secret from Kubernetes API
// server, and converts its fields from byte array to their corresponding data types.
func (c *Client) GetHelmState(ctx context.Context, namespace string, secretName string) (*helm.State, error) {
	helmSecret, err := c.GetSecret(ctx, namespace, secretName, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("unable to retrieve helm values secret %s/%s: %w", namespace, secretName, err)
	}
	versionBytes, ok := helmSecret.Data[defaults.HelmChartVersionSecretKeyName]
	if !ok {
		return nil, fmt.Errorf("unable to retrieve helm chart version from secret %s/%s: %w", namespace, secretName, err)
	}
	versionString := string(versionBytes)
	version, err := utils.ParseCiliumVersion(versionString)
	if err != nil {
		return nil, fmt.Errorf("unable to parse helm chart version from secret %s/%s: %s %w", namespace, secretName, versionString, err)
	}

	yamlSecret, ok := helmSecret.Data[defaults.HelmValuesSecretKeyName]
	if !ok {
		return nil, fmt.Errorf("unable to retrieve helm values from secret %s/%s: %w", namespace, secretName, err)
	}

	values, err := chartutil.ReadValues(yamlSecret)
	if err != nil {
		return nil, fmt.Errorf("unable to parse helm values from secret %s/%s: %w", namespace, secretName, err)
	}
	return &helm.State{
		Secret:  helmSecret,
		Version: version,
		Values:  values,
	}, nil
}

func (c *Client) ListAPIResources(ctx context.Context) ([]string, error) {
	lists, err := c.Clientset.Discovery().ServerPreferredResources()
	if err != nil {
		return nil, fmt.Errorf("failed to list api resources: %w", err)
	}
	results := make([]string, 0, len(lists))
	for _, list := range lists {
		results = append(results, list.GroupVersion)
	}
	return results, nil
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

// Tetragon Specific commands

func (c *Client) ListTetragonTracingPolicies(ctx context.Context, opts metav1.ListOptions) (*tetragonv1alpha1.TracingPolicyList, error) {
	return c.TetragonClientset.CiliumV1alpha1().TracingPolicies().List(ctx, opts)
}
