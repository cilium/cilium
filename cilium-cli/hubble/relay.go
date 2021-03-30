// Copyright 2020-2021 Authors of Cilium
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
	"os/exec"
	"time"

	"github.com/cilium/cilium-cli/defaults"
	"github.com/cilium/cilium-cli/internal/k8s"
	"github.com/cilium/cilium-cli/internal/utils"

	"github.com/cloudflare/cfssl/config"
	"github.com/cloudflare/cfssl/csr"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
)

const (
	relayPort     = int32(defaults.RelayPort)
	relayPortName = "grpc"
)

var (
	relayReplicas            = int32(1)
	relayPortIntstr          = intstr.FromInt(defaults.RelayPort)
	deploymentMaxSurge       = intstr.FromInt(1)
	deploymentMaxUnavailable = intstr.FromInt(1)
)

var relayClusterRole = &rbacv1.ClusterRole{
	ObjectMeta: metav1.ObjectMeta{
		Name: defaults.RelayClusterRoleName,
	},
	Rules: []rbacv1.PolicyRule{
		{
			APIGroups: []string{""},
			Resources: []string{"componentstatuses", "endpoints", "namespaces", "nodes", "pods", "services"},
			Verbs:     []string{"get", "list", "watch"},
		},
	},
}

func (k *K8sHubble) generateRelayService() *corev1.Service {
	// NOTE: assuming "disable-server-tls: true", see generateRelayConfigMap().
	s := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:   defaults.RelayServiceName,
			Labels: defaults.RelayDeploymentLabels,
		},
		Spec: corev1.ServiceSpec{
			Type: corev1.ServiceType(k.params.RelayServiceType),
			Ports: []corev1.ServicePort{
				{
					Port:       int32(defaults.RelayServicePlaintextPort),
					TargetPort: relayPortIntstr,
				},
			},
			Selector: defaults.RelayDeploymentLabels,
		},
	}
	return s
}

func (k *K8sHubble) generateRelayDeployment() *appsv1.Deployment {
	d := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:   defaults.RelayDeploymentName,
			Labels: defaults.RelayDeploymentLabels,
		},
		Spec: appsv1.DeploymentSpec{
			Replicas: &relayReplicas,
			Selector: &metav1.LabelSelector{
				MatchLabels: defaults.RelayDeploymentLabels,
			},
			Strategy: appsv1.DeploymentStrategy{
				Type: appsv1.RollingUpdateDeploymentStrategyType,
				RollingUpdate: &appsv1.RollingUpdateDeployment{
					MaxUnavailable: &deploymentMaxUnavailable,
					MaxSurge:       &deploymentMaxSurge,
				},
			},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Name:   defaults.RelayDeploymentName,
					Labels: defaults.RelayDeploymentLabels,
				},
				Spec: corev1.PodSpec{
					RestartPolicy:      corev1.RestartPolicyAlways,
					ServiceAccountName: defaults.RelayServiceAccountName,
					Containers: []corev1.Container{
						{
							Name:    "hubble-relay",
							Command: []string{"hubble-relay"},
							Args: []string{
								"serve",
							},
							Image:           k.relayImage(),
							ImagePullPolicy: corev1.PullIfNotPresent,
							Ports: []corev1.ContainerPort{
								{
									Name:          relayPortName,
									ContainerPort: relayPort,
								},
							},
							VolumeMounts: []corev1.VolumeMount{
								{
									Name:      "hubble-sock-dir",
									MountPath: "/var/run/cilium",
									ReadOnly:  true,
								},
								{
									Name:      "config",
									MountPath: "/etc/hubble-relay",
									ReadOnly:  true,
								},
								{
									Name:      "tls",
									MountPath: "/var/lib/hubble-relay/tls",
									ReadOnly:  true,
								},
							},
							ReadinessProbe: &corev1.Probe{
								Handler: corev1.Handler{
									TCPSocket: &corev1.TCPSocketAction{
										Port: relayPortIntstr,
									},
								},
							},
							LivenessProbe: &corev1.Probe{
								Handler: corev1.Handler{
									TCPSocket: &corev1.TCPSocketAction{
										Port: relayPortIntstr,
									},
								},
							},
						},
					},
					Volumes: []corev1.Volume{
						{
							Name: "config",
							VolumeSource: corev1.VolumeSource{
								ConfigMap: &corev1.ConfigMapVolumeSource{
									LocalObjectReference: corev1.LocalObjectReference{
										Name: defaults.RelayConfigMapName,
									},
									Items: []corev1.KeyToPath{
										{Key: "config.yaml", Path: "config.yaml"},
									},
								},
							},
						},
						{
							Name: "hubble-sock-dir",
							VolumeSource: corev1.VolumeSource{
								HostPath: &corev1.HostPathVolumeSource{
									Path: "/var/run/cilium",
									Type: &hostPathDirectoryOrCreate,
								},
							},
						},
						{
							Name: "tls",
							VolumeSource: corev1.VolumeSource{
								Projected: &corev1.ProjectedVolumeSource{
									Sources: []corev1.VolumeProjection{
										{
											Secret: &corev1.SecretProjection{
												LocalObjectReference: corev1.LocalObjectReference{
													Name: defaults.RelayClientSecretName,
												},
												Items: []corev1.KeyToPath{
													{
														Key:  corev1.TLSCertKey,
														Path: "client.crt",
													},
													{
														Key:  corev1.TLSPrivateKeyKey,
														Path: "client.key",
													},
												},
											},
										},
										{
											Secret: &corev1.SecretProjection{
												LocalObjectReference: corev1.LocalObjectReference{
													Name: defaults.CASecretName,
												},
												Items: []corev1.KeyToPath{
													{
														Key:  defaults.CASecretCertName,
														Path: "hubble-server-ca.crt",
													},
												},
											},
										},
									},
								},
							},
						},
						//{{- if .Values.hubble.relay.tls.server.enabled }}
						//          - secret:
						//              name: hubble-relay-server-certs
						//              items:
						//                - key: tls.crt
						//                  path: server.crt
						//                - key: tls.key
						//                  path: server.key
						//{{- end }}
					},
				},
			},
		},
	}
	return d
}

func (k *K8sHubble) generateRelayConfigMap() *corev1.ConfigMap {

	var config = `
peer-service: ` + defaults.HubbleSocketPath + `
listen-address: ` + fmt.Sprintf("%s:%d", defaults.RelayListenHost, defaults.RelayPort) + `
dial-timeout: ~
retry-timeout: ~
sort-buffer-len-max: ~
sort-buffer-drain-timeout: ~
tls-client-cert-file: /var/lib/hubble-relay/tls/client.crt
tls-client-key-file: /var/lib/hubble-relay/tls/client.key
tls-hubble-server-ca-files: /var/lib/hubble-relay/tls/hubble-server-ca.crt
disable-server-tls: true
`

	//{{- if .Values.hubble.relay.tls.server.enabled }}
	//tls-server-cert-file: /var/lib/hubble-relay/tls/server.crt
	//tls-server-key-file: /var/lib/hubble-relay/tls/server.key
	//{{- else }}
	//{{- end }}
	//{{- end }}

	return &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name: defaults.RelayConfigMapName,
		},
		Data: map[string]string{
			"config.yaml": config,
		},
	}
}

func (k *K8sHubble) relayImage() string {
	return utils.BuildImagePath(k.params.RelayImage, defaults.AgentImage, k.params.RelayVersion, defaults.Version)
}

func (k *K8sHubble) disableRelay(ctx context.Context) error {
	k.Log("🔥 Deleting Relay...")
	k.client.DeleteService(ctx, k.params.Namespace, defaults.RelayServiceName, metav1.DeleteOptions{})
	k.client.DeleteDeployment(ctx, k.params.Namespace, defaults.RelayDeploymentName, metav1.DeleteOptions{})
	k.client.DeleteClusterRoleBinding(ctx, defaults.RelayClusterRoleName, metav1.DeleteOptions{})
	k.client.DeleteClusterRole(ctx, defaults.RelayClusterRoleName, metav1.DeleteOptions{})
	k.client.DeleteServiceAccount(ctx, k.params.Namespace, defaults.RelayServiceAccountName, metav1.DeleteOptions{})
	k.client.DeleteConfigMap(ctx, k.params.Namespace, defaults.RelayConfigMapName, metav1.DeleteOptions{})

	k.deleteRelayCertificates(ctx)

	return nil
}

func (k *K8sHubble) enableRelay(ctx context.Context) error {
	_, err := k.client.GetDeployment(ctx, k.params.Namespace, defaults.RelayDeploymentName, metav1.GetOptions{})
	if err == nil {
		k.Log("✅ Relay is already deployed")
		return nil
	}

	if err := k.createRelayCertificates(ctx); err != nil {
		return err
	}

	//	k.Log("✨ Generating certificates...")

	k.Log("✨ Deploying Relay...")
	if _, err := k.client.CreateConfigMap(ctx, k.params.Namespace, k.generateRelayConfigMap(), metav1.CreateOptions{}); err != nil {
		return err
	}

	if _, err := k.client.CreateServiceAccount(ctx, k.params.Namespace, k8s.NewServiceAccount(defaults.RelayServiceAccountName), metav1.CreateOptions{}); err != nil {
		return err
	}

	if _, err := k.client.CreateClusterRole(ctx, relayClusterRole, metav1.CreateOptions{}); err != nil {
		return err
	}

	if _, err := k.client.CreateClusterRoleBinding(ctx, k8s.NewClusterRoleBinding(defaults.RelayClusterRoleName, k.params.Namespace, defaults.RelayServiceAccountName), metav1.CreateOptions{}); err != nil {
		return err
	}

	if _, err := k.client.CreateDeployment(ctx, k.params.Namespace, k.generateRelayDeployment(), metav1.CreateOptions{}); err != nil {
		return err
	}

	//relayService.Spec.Type = corev1.ServiceType(k.params.ServiceType)
	if _, err := k.client.CreateService(ctx, k.params.Namespace, k.generateRelayService(), metav1.CreateOptions{}); err != nil {
		return err
	}

	return nil
}

func (k *K8sHubble) deleteRelayCertificates(ctx context.Context) error {
	k.Log("🔥 Deleting Relay certificates...")
	k.client.DeleteSecret(ctx, k.params.Namespace, defaults.RelayServerSecretName, metav1.DeleteOptions{})
	k.client.DeleteSecret(ctx, k.params.Namespace, defaults.RelayClientSecretName, metav1.DeleteOptions{})
	return nil
}

func (k *K8sHubble) createRelayCertificates(ctx context.Context) error {
	k.Log("🔑 Generating certificates for Relay...")
	if err := k.createRelayServerCertificate(ctx); err != nil {
		return err
	}

	return k.createRelayClientCertificate(ctx)
}

func (k *K8sHubble) createRelayServerCertificate(ctx context.Context) error {
	certReq := &csr.CertificateRequest{
		Names:      []csr.Name{{C: "US", ST: "San Francisco", L: "CA"}},
		KeyRequest: csr.NewKeyRequest(),
		Hosts:      []string{"*.hubble-relay.cilium.io"},
		CN:         "*.hubble-relay.cilium.io",
	}

	signConf := &config.Signing{
		Default: &config.SigningProfile{Expiry: 5 * 365 * 24 * time.Hour},
		Profiles: map[string]*config.SigningProfile{
			defaults.RelayServerSecretName: {
				Expiry: 3 * 365 * 24 * time.Hour,
				Usage:  []string{"signing", "key encipherment", "server auth", "client auth"},
			},
		},
	}

	cert, key, err := k.certManager.GenerateCertificate(defaults.RelayServerSecretName, certReq, signConf)
	if err != nil {
		return fmt.Errorf("unable to generate certificate %s: %w", defaults.RelayServerSecretName, err)
	}

	data := map[string][]byte{
		corev1.TLSCertKey:         cert,
		corev1.TLSPrivateKeyKey:   key,
		defaults.CASecretCertName: k.certManager.CACertBytes(),
	}

	_, err = k.client.CreateSecret(ctx, k.params.Namespace, k8s.NewTLSSecret(defaults.RelayServerSecretName, k.params.Namespace, data), metav1.CreateOptions{})
	if err != nil {
		return fmt.Errorf("unable to create secret %s/%s: %w", k.params.Namespace, defaults.RelayServerSecretName, err)
	}

	return nil
}

func (k *K8sHubble) createRelayClientCertificate(ctx context.Context) error {
	certReq := &csr.CertificateRequest{
		Names:      []csr.Name{{C: "US", ST: "San Francisco", L: "CA"}},
		KeyRequest: csr.NewKeyRequest(),
		Hosts:      []string{"*.hubble-relay.cilium.io"},
		CN:         "*.hubble-relay.cilium.io",
	}

	signConf := &config.Signing{
		Default: &config.SigningProfile{Expiry: 5 * 365 * 24 * time.Hour},
		Profiles: map[string]*config.SigningProfile{
			defaults.RelayClientSecretName: {
				Expiry: 3 * 365 * 24 * time.Hour,
				Usage:  []string{"signing", "key encipherment", "server auth", "client auth"},
			},
		},
	}

	cert, key, err := k.certManager.GenerateCertificate(defaults.RelayClientSecretName, certReq, signConf)
	if err != nil {
		return fmt.Errorf("unable to generate certificate %s: %w", defaults.RelayClientSecretName, err)
	}

	data := map[string][]byte{
		corev1.TLSCertKey:         cert,
		corev1.TLSPrivateKeyKey:   key,
		defaults.CASecretCertName: k.certManager.CACertBytes(),
	}

	_, err = k.client.CreateSecret(ctx, k.params.Namespace, k8s.NewTLSSecret(defaults.RelayClientSecretName, k.params.Namespace, data), metav1.CreateOptions{})
	if err != nil {
		return fmt.Errorf("unable to create secret %s/%s: %w", k.params.Namespace, defaults.RelayClientSecretName, err)
	}

	return nil
}

func (k *K8sHubble) PortForwardCommand(ctx context.Context) error {
	cmd := "kubectl"
	args := []string{
		"port-forward",
		"-n", k.params.Namespace,
		"svc/hubble-relay",
		"--address", "0.0.0.0",
		"--address", "::",
		fmt.Sprintf("%d:%d", k.params.PortForward, defaults.RelayServicePlaintextPort)}

	c := exec.Command(cmd, args...)
	c.Stdout = k.params.Writer
	c.Stderr = k.params.Writer

	if err := c.Run(); err != nil {
		return fmt.Errorf("unable to execute command %s %v: %s", cmd, args, err)
	}

	return nil
}
