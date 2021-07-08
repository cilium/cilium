// Copyright 2020 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package k8s

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"
	"time"

	"github.com/cilium/cilium/api/v1/models"
	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	ciliumClientset "github.com/cilium/cilium/pkg/k8s/client/clientset/versioned"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/cli-runtime/pkg/genericclioptions"
	"k8s.io/cli-runtime/pkg/resource"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"

	// Register all auth providers (azure, gcp, oidc, openstack, ..).
	_ "k8s.io/client-go/plugin/pkg/client/auth"
)

type Client struct {
	Clientset        kubernetes.Interface
	DynamicClientset dynamic.Interface
	CiliumClientset  ciliumClientset.Interface
	Config           *rest.Config
	RawConfig        clientcmdapi.Config
	restClientGetter genericclioptions.RESTClientGetter
	contextName      string
}

func NewClient(contextName, kubeconfig string) (*Client, error) {
	// Register the Cilium types in the default scheme.
	_ = ciliumv2.AddToScheme(scheme.Scheme)

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

	dynamicClientset, err := dynamic.NewForConfig(config)
	if err != nil {
		return nil, err
	}

	if contextName == "" {
		contextName = rawConfig.CurrentContext
	}

	return &Client{
		CiliumClientset:  ciliumClientset,
		Clientset:        clientset,
		Config:           config,
		DynamicClientset: dynamicClientset,
		RawConfig:        rawConfig,
		restClientGetter: &restClientGetter,
		contextName:      contextName,
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

func (c *Client) CreateSecret(ctx context.Context, namespace string, secret *corev1.Secret, opts metav1.CreateOptions) (*corev1.Secret, error) {
	return c.Clientset.CoreV1().Secrets(namespace).Create(ctx, secret, opts)
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

// CheckDaemonSetStatus returns nil if the daemonset is ready, or a non-nil error otherwise.
// This function considers a daemonset ready if all the pods in the daemonset is in ready
// state.
func (c *Client) CheckDaemonSetStatus(ctx context.Context, namespace, daemonset string) error {
	d, err := c.GetDaemonSet(ctx, namespace, daemonset, metav1.GetOptions{})
	if err != nil {
		return err
	}

	if d == nil {
		return fmt.Errorf("daemonset is not available")
	}

	if d.Status.ObservedGeneration != d.Generation {
		return fmt.Errorf("observed generation (%d) is older than generation of the desired state (%d)",
			d.Status.ObservedGeneration, d.Generation)
	}

	if d.Status.DesiredNumberScheduled != d.Status.NumberReady {
		return fmt.Errorf("not all pods ready: desired %d ready %d", d.Status.DesiredNumberScheduled, d.Status.NumberReady)
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
		Container:  "cilium-agent",
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

func (c *Client) CiliumStatus(ctx context.Context, namespace, pod string) (*models.StatusResponse, error) {
	stdout, err := c.ExecInPod(ctx, namespace, pod, "cilium-agent", []string{"cilium", "status", "-o", "json"})
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

func (c *Client) DeleteDaemonSet(ctx context.Context, namespace, name string, opts metav1.DeleteOptions) error {
	return c.Clientset.AppsV1().DaemonSets(namespace).Delete(ctx, name, opts)
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
)

func (k Kind) String() string {
	switch k {
	case KindUnknown:
		return "unknown"
	case KindMicrok8s:
		return "microk8s"
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
	default:
		return "invalid"
	}
}

type Flavor struct {
	ClusterName string
	Kind        Kind
}

func (c *Client) AutodetectFlavor(ctx context.Context) (f Flavor, err error) {
	f = Flavor{
		ClusterName: c.ClusterName(),
	}

	if c.ClusterName() == "minikube" || c.ContextName() == "minikube" {
		f.Kind = KindMinikube
		return
	}

	if strings.HasPrefix(c.ClusterName(), "microk8s-") || c.ContextName() == "microk8s" {
		f.Kind = KindMicrok8s
	}

	// When creating a cluster with kind create cluster --name foo,
	// the context and cluster name are kind-foo.
	if strings.HasPrefix(c.ClusterName(), "kind-") || strings.HasPrefix(c.ContextName(), "kind-") {
		f.Kind = KindKind
		return
	}

	if strings.HasPrefix(c.ClusterName(), "gke_") {
		f.Kind = KindGKE
		return
	}

	// When creating a cluster with eksctl create cluster --name foo,
	// the cluster name is foo.<region>.eksctl.io
	if strings.HasSuffix(c.ClusterName(), ".eksctl.io") {
		f.ClusterName = strings.ReplaceAll(c.ClusterName(), ".", "-")
		f.Kind = KindEKS
		return
	}

	if context, ok := c.RawConfig.Contexts[c.ContextName()]; ok {
		if cluster, ok := c.RawConfig.Clusters[context.Cluster]; ok {
			if strings.HasSuffix(cluster.Server, "eks.amazonaws.com") {
				f.Kind = KindEKS
				return
			}

			if strings.HasSuffix(cluster.Server, "azmk8s.io:443") {
				f.Kind = KindAKS
				return
			}
		}
	}

	return
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

func (c *Client) ListNodes(ctx context.Context, options metav1.ListOptions) (*corev1.NodeList, error) {
	return c.Clientset.CoreV1().Nodes().List(ctx, options)
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

func (c *Client) ListCiliumClusterwideNetworkPolicies(ctx context.Context, opts metav1.ListOptions) (*ciliumv2.CiliumClusterwideNetworkPolicyList, error) {
	return c.CiliumClientset.CiliumV2().CiliumClusterwideNetworkPolicies().List(ctx, opts)
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
	r := resource.NewBuilder(c.restClientGetter).
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

func (c *Client) ListNetworkPolicies(ctx context.Context, o metav1.ListOptions) (*networkingv1.NetworkPolicyList, error) {
	return c.Clientset.NetworkingV1().NetworkPolicies(corev1.NamespaceAll).List(ctx, o)
}

func (c *Client) ListCiliumIdentities(ctx context.Context) (*ciliumv2.CiliumIdentityList, error) {
	return c.CiliumClientset.CiliumV2().CiliumIdentities().List(ctx, metav1.ListOptions{})
}

func (c *Client) ListCiliumNodes(ctx context.Context) (*ciliumv2.CiliumNodeList, error) {
	return c.CiliumClientset.CiliumV2().CiliumNodes().List(ctx, metav1.ListOptions{})
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

func (c *Client) GetRunningCiliumVersion(ctx context.Context, namespace string) (string, error) {
	pods, err := c.ListPods(ctx, namespace, metav1.ListOptions{LabelSelector: "k8s-app=cilium"})
	if err != nil {
		return "", fmt.Errorf("unable to list cilium pods: %w", err)
	}
	if len(pods.Items) > 0 && len(pods.Items[0].Spec.Containers) > 0 {
		image := pods.Items[0].Spec.Containers[0].Image
		version := strings.SplitN(image, ":", 2)
		if len(version) != 2 {
			return "", errors.New("unable to extract cilium version from container image")
		}
		return version[1], nil
	}
	return "", errors.New("unable to obtain cilium version: no cilium pods found")
}
