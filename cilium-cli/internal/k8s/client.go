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
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/cilium/cilium/api/v1/models"
	ciliumClientset "github.com/cilium/cilium/pkg/k8s/client/clientset/versioned"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
)

type Client struct {
	Clientset       kubernetes.Interface
	CiliumClientset ciliumClientset.Interface
	Config          *rest.Config
	RawConfig       clientcmdapi.Config
}

func NewClient(contextName string) (*Client, error) {
	nonInteractiveClient := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(
		clientcmd.NewDefaultClientConfigLoadingRules(),
		&clientcmd.ConfigOverrides{CurrentContext: contextName},
	)

	config, err := nonInteractiveClient.ClientConfig()
	if err != nil {
		return nil, err
	}

	rawConfig, err := nonInteractiveClient.RawConfig()
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

	return &Client{
		CiliumClientset: ciliumClientset,
		Clientset:       clientset,
		Config:          config,
		RawConfig:       rawConfig,
	}, nil
}

// ContextName returns the name of the context the client is connected to
func (c *Client) ContextName() (name string) {
	return c.RawConfig.CurrentContext
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

func (c *Client) DeploymentIsReady(ctx context.Context, namespace, deployment string) error {
	d, err := c.GetDeployment(ctx, namespace, deployment, metav1.GetOptions{})
	if err != nil {
		return err
	}

	if d == nil {
		return fmt.Errorf("deployment is not available")
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

func (c *Client) ListPods(ctx context.Context, namespace string, options metav1.ListOptions) (*corev1.PodList, error) {
	return c.Clientset.CoreV1().Pods(namespace).List(ctx, options)
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
	KindEKS
)

func (k Kind) String() string {
	switch k {
	case KindUnknown:
		return "unknown"
	case KindMinikube:
		return "minikube"
	case KindEKS:
		return "EKS"
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

	if context, ok := c.RawConfig.Contexts[c.ContextName()]; ok {
		if cluster, ok := c.RawConfig.Clusters[context.Cluster]; ok {
			if strings.HasSuffix(cluster.Server, "eks.amazonaws.com") {
				f.Kind = KindEKS
				return
			}
		}
	}

	return
}
