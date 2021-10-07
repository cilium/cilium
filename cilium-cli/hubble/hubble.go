// SPDX-License-Identifier: Apache-2.0
// Copyright 2020 Authors of Cilium

package hubble

import (
	"context"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/cilium/cilium-cli/defaults"
	"github.com/cilium/cilium-cli/internal/certs"
	"github.com/cilium/cilium-cli/internal/utils"
	"github.com/cilium/cilium-cli/status"

	"github.com/cilium/cilium/api/v1/models"
	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
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
	PatchConfigMap(ctx context.Context, namespace, name string, pt types.PatchType, data []byte, opts metav1.PatchOptions) (*corev1.ConfigMap, error)
	CreateDeployment(ctx context.Context, namespace string, deployment *appsv1.Deployment, opts metav1.CreateOptions) (*appsv1.Deployment, error)
	GetDeployment(ctx context.Context, namespace, name string, opts metav1.GetOptions) (*appsv1.Deployment, error)
	DeleteDeployment(ctx context.Context, namespace, name string, opts metav1.DeleteOptions) error
	CreateService(ctx context.Context, namespace string, service *corev1.Service, opts metav1.CreateOptions) (*corev1.Service, error)
	DeleteService(ctx context.Context, namespace, name string, opts metav1.DeleteOptions) error
	DeletePodCollection(ctx context.Context, namespace string, opts metav1.DeleteOptions, listOpts metav1.ListOptions) error
	ListPods(ctx context.Context, namespace string, options metav1.ListOptions) (*corev1.PodList, error)
	GetDaemonSet(ctx context.Context, namespace, name string, opts metav1.GetOptions) (*appsv1.DaemonSet, error)
	CiliumStatus(ctx context.Context, namespace, pod string) (*models.StatusResponse, error)
	ListCiliumEndpoints(ctx context.Context, namespace string, opts metav1.ListOptions) (*ciliumv2.CiliumEndpointList, error)
	GetRunningCiliumVersion(ctx context.Context, namespace string) (string, error)
}

type K8sHubble struct {
	client        k8sHubbleImplementation
	params        Parameters
	certManager   *certs.CertManager
	ciliumVersion string
}

type Parameters struct {
	Namespace        string
	Relay            bool
	RelayImage       string
	RelayVersion     string
	RelayServiceType string
	PortForward      int
	CreateCA         bool
	UI               bool
	UIPortForward    int
	Writer           io.Writer
	Context          string // Only for 'kubectl' pass-through commands
	Wait             bool
	WaitDuration     time.Duration
}

func (p *Parameters) Log(format string, a ...interface{}) {
	fmt.Fprintf(p.Writer, format+"\n", a...)
}

func (p *Parameters) validateParams() error {
	if p.RelayImage != defaults.RelayImage {
		return nil
	} else if !utils.CheckVersion(p.RelayVersion) && p.RelayVersion != "" {
		return fmt.Errorf("invalid syntax %q for image tag", p.RelayVersion)
	}
	return nil
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

var hubbleCfg = map[string]string{
	// Enable Hubble gRPC service.
	"enable-hubble": "true",
	// UNIX domain socket for Hubble server to listen to.
	"hubble-socket-path": defaults.HubbleSocketPath,
	// An additional address for Hubble server to listen to (e.g. ":4244").
	"hubble-listen-address":      ":4244",
	"hubble-disable-tls":         "false",
	"hubble-tls-cert-file":       "/var/lib/cilium/tls/hubble/server.crt",
	"hubble-tls-key-file":        "/var/lib/cilium/tls/hubble/server.key",
	"hubble-tls-client-ca-files": "/var/lib/cilium/tls/hubble/client-ca.crt",
}

func (k *K8sHubble) disableHubble(ctx context.Context) error {
	cm, err := k.client.GetConfigMap(ctx, k.params.Namespace, defaults.ConfigMapName, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("unable to get ConfigMap %s: %w", defaults.ConfigMapName, err)
	}

	var changes []string
	for k := range hubbleCfg {
		if _, ok := cm.Data[k]; ok {
			changes = append(changes, `{"op": "remove", "path": "/data/`+k+`"}`)
		}
	}
	if len(changes) > 0 {
		patch := []byte(`[` + strings.Join(changes, ",") + `]`)

		k.Log("✨ Patching ConfigMap %s to disable Hubble...", defaults.ConfigMapName)
		_, err := k.client.PatchConfigMap(ctx, k.params.Namespace, defaults.ConfigMapName, types.JSONPatchType, patch, metav1.PatchOptions{})
		if err != nil {
			return fmt.Errorf("unable to patch ConfigMap %s with patch %q: %w", defaults.ConfigMapName, patch, err)
		}
	}

	if err := k.client.DeletePodCollection(ctx, k.params.Namespace, metav1.DeleteOptions{}, metav1.ListOptions{LabelSelector: defaults.CiliumPodSelector}); err != nil {
		k.Log("⚠️  Unable to restart Clium pods: %s", err)
	} else {
		k.Log("♻️  Restarted Cilium pods")
	}

	return nil
}

func (k *K8sHubble) Disable(ctx context.Context) error {
	if err := k.disableUI(ctx); err != nil {
		return err
	}

	if err := k.disableRelay(ctx); err != nil {
		return err
	}

	if err := k.disableHubble(ctx); err != nil {
		return err
	}

	k.Log("✅ Hubble was successfully disabled.")

	return nil
}

func (k *K8sHubble) enableHubble(ctx context.Context) error {
	var changes []string
	for k, v := range hubbleCfg {
		changes = append(changes, `"`+k+`":"`+v+`"`)
	}

	patch := []byte(`{"data":{` + strings.Join(changes, ",") + `}}`)

	k.Log("✨ Patching ConfigMap %s to enable Hubble...", defaults.ConfigMapName)
	_, err := k.client.PatchConfigMap(ctx, k.params.Namespace, defaults.ConfigMapName, types.StrategicMergePatchType, patch, metav1.PatchOptions{})
	if err != nil {
		return fmt.Errorf("unable to patch ConfigMap %s with patch %q: %w", defaults.ConfigMapName, patch, err)
	}

	if err := k.client.DeletePodCollection(ctx, k.params.Namespace, metav1.DeleteOptions{}, metav1.ListOptions{LabelSelector: defaults.CiliumPodSelector}); err != nil {
		k.Log("⚠️  Unable to restart Clium pods: %s", err)
	} else {
		k.Log("♻️  Restarted Cilium pods")
	}

	return nil
}

func (k *K8sHubble) Enable(ctx context.Context) error {
	if err := k.params.validateParams(); err != nil {
		return err
	}

	var err error
	k.ciliumVersion, err = k.client.GetRunningCiliumVersion(ctx, k.params.Namespace)
	if err != nil {
		return err
	}

	err = k.certManager.LoadCAFromK8s(ctx)
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

	if err := k.enableHubble(ctx); err != nil {
		return err
	}

	var dur time.Duration
	if k.params.Relay || k.params.UI {
		start := time.Now()
		k.Log("⌛ Waiting for Cilium to become ready before deploying other Hubble component(s)...")
		collector, err := status.NewK8sStatusCollector(k.client, status.K8sStatusParameters{
			Namespace:       k.params.Namespace,
			Wait:            true,
			WaitDuration:    k.params.WaitDuration,
			WarningFreePods: []string{defaults.AgentDaemonSetName, defaults.OperatorDeploymentName},
		})
		if err != nil {
			return err
		}
		dur = time.Since(start)

		s, err := collector.Status(ctx)
		if err != nil {
			fmt.Println(s.Format())
			return err
		}
	}

	if k.params.Relay {
		if err := k.enableRelay(ctx); err != nil {
			return err
		}
	}

	if k.params.UI {
		if err := k.enableUI(ctx); err != nil {
			return err
		}
	}

	if k.params.Wait {
		var pods []string

		if k.params.Relay {
			pods = append(pods, defaults.RelayDeploymentName)
		}
		if k.params.UI {
			pods = append(pods, defaults.HubbleUIDeploymentName)
		}

		k.Log("⌛ Waiting for Hubble to be installed...")
		collector, err := status.NewK8sStatusCollector(k.client, status.K8sStatusParameters{
			Namespace:       k.params.Namespace,
			Wait:            true,
			WaitDuration:    k.params.WaitDuration - dur,
			WarningFreePods: pods,
		})
		if err != nil {
			return err
		}

		s, err := collector.Status(ctx)
		if err != nil {
			fmt.Println(s.Format())
			return err
		}
	}

	k.Log("✅ Hubble was successfully enabled!")

	return nil
}
