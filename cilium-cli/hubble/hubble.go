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

package hubble

import (
	"context"
	"fmt"
	"io"
	"strings"

	"github.com/cilium/cilium-cli/defaults"
	"github.com/cilium/cilium-cli/internal/certs"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	configNameEnableHubble  = "enable-hubble"
	configNameListenAddress = "hubble-listen-address"
)

var (
	hostPathDirectoryOrCreate = corev1.HostPathDirectoryOrCreate
)

type k8sHubbleImplementation interface {
	CreateSecret(ctx context.Context, namespace string, secret *corev1.Secret, opts metav1.CreateOptions) (*corev1.Secret, error)
	DeleteSecret(ctx context.Context, namespace, name string, opts metav1.DeleteOptions) error
	GetSecret(ctx context.Context, namespace, name string, opts metav1.GetOptions) (*corev1.Secret, error)
	CreateServiceAccount(ctx context.Context, namespace string, account *corev1.ServiceAccount, opts metav1.CreateOptions) (*corev1.ServiceAccount, error)
	DeleteServiceAccount(ctx context.Context, namespace, name string, opts metav1.DeleteOptions) error
	CreateClusterRole(ctx context.Context, role *rbacv1.ClusterRole, opts metav1.CreateOptions) (*rbacv1.ClusterRole, error)
	DeleteClusterRole(ctx context.Context, name string, opts metav1.DeleteOptions) error
	CreateClusterRoleBinding(ctx context.Context, role *rbacv1.ClusterRoleBinding, opts metav1.CreateOptions) (*rbacv1.ClusterRoleBinding, error)
	DeleteClusterRoleBinding(ctx context.Context, name string, opts metav1.DeleteOptions) error
	CreateConfigMap(ctx context.Context, namespace string, config *corev1.ConfigMap, opts metav1.CreateOptions) (*corev1.ConfigMap, error)
	DeleteConfigMap(ctx context.Context, namespace, name string, opts metav1.DeleteOptions) error
	GetConfigMap(ctx context.Context, namespace, name string, opts metav1.GetOptions) (*corev1.ConfigMap, error)
	CreateDeployment(ctx context.Context, namespace string, deployment *appsv1.Deployment, opts metav1.CreateOptions) (*appsv1.Deployment, error)
	GetDeployment(ctx context.Context, namespace, name string, opts metav1.GetOptions) (*appsv1.Deployment, error)
	DeleteDeployment(ctx context.Context, namespace, name string, opts metav1.DeleteOptions) error
	CreateService(ctx context.Context, namespace string, service *corev1.Service, opts metav1.CreateOptions) (*corev1.Service, error)
	DeleteService(ctx context.Context, namespace, name string, opts metav1.DeleteOptions) error
	//	GetService(ctx context.Context, namespace, name string, opts metav1.GetOptions) (*corev1.Service, error)
}

type K8sHubble struct {
	client      k8sHubbleImplementation
	params      Parameters
	certManager *certs.CertManager
}

type Parameters struct {
	Namespace        string
	Relay            bool
	RelayImage       string
	RelayVersion     string
	RelayServiceType string
	CreateCA         bool
	Writer           io.Writer
}

func NewK8sHubble(client k8sHubbleImplementation, p Parameters) *K8sHubble {
	cm := certs.NewCertManager(client, certs.Parameters{Namespace: p.Namespace})

	return &K8sHubble{
		client:      client,
		params:      p,
		certManager: cm,
	}
}

func (k *K8sHubble) Log(format string, a ...interface{}) {
	fmt.Fprintf(k.params.Writer, format+"\n", a...)
}

func (k *K8sHubble) Validate(ctx context.Context) error {
	var failures int
	k.Log("✨ Validating cluster configuration...")

	cm, err := k.client.GetConfigMap(ctx, k.params.Namespace, defaults.ConfigMapName, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("unable to retrieve ConfigMap %q: %w", defaults.ConfigMapName, err)
	}

	if cm.Data == nil {
		return fmt.Errorf("ConfigMap %q does not contain any configuration", defaults.ConfigMapName)
	}

	enableHubble, ok := cm.Data[configNameEnableHubble]
	if !ok {
		k.Log("❌ Hubble is not enabled in ConfigMap, %q is not set", configNameEnableHubble)
		failures++
	}

	if strings.ToLower(enableHubble) != "true" {
		k.Log("❌ Hubble is not enabled in ConfigMap, %q=%q must be set to true", configNameEnableHubble, enableHubble)
		failures++
	}

	_, ok = cm.Data[configNameListenAddress]
	if !ok {
		k.Log("❌ Hubble is not configured to listen on a network port, %q is not set", configNameListenAddress)
		failures++
	}

	if failures > 0 {
		return fmt.Errorf("%d validation errors", failures)
	}

	k.Log("✅ Valid configuration found")

	return nil

}

func (k *K8sHubble) Disable(ctx context.Context) error {
	return k.disableRelay(ctx)
}

func (k *K8sHubble) Enable(ctx context.Context) error {
	err := k.certManager.LoadCAFromK8s(ctx)
	if err != nil {
		if !k.params.CreateCA {
			k.Log("❌ Cilium CA not found: %s", err)
			return err
		}

		k.Log("🔑 Generating CA...")
		if err := k.certManager.GenerateCA(); err != nil {
			return fmt.Errorf("unable to generate CA: %w", err)
		}

		if err := k.certManager.StoreCAInK8s(ctx); err != nil {
			return fmt.Errorf("unable to store CA in secret: %w", err)
		}
	} else {
		k.Log("🔑 Found existing CA in secret %s", defaults.CASecretName)
	}

	if k.params.Relay {
		if err := k.enableRelay(ctx); err != nil {
			return err
		}
	}

	return nil
}
