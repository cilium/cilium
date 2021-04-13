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
	"os/exec"
	"time"

	"github.com/cilium/cilium-cli/defaults"
	"github.com/cilium/cilium-cli/internal/k8s"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
)

var (
	hubbleUIReplicas   = int32(1)
	hubbleUIPortIntstr = intstr.FromInt(8081)
	hubbleUIUser       = int64(10001)
)

var hubbleUIClusterRole = &rbacv1.ClusterRole{
	ObjectMeta: metav1.ObjectMeta{
		Name: defaults.HubbleUIClusterRoleName,
	},
	Rules: []rbacv1.PolicyRule{
		{
			APIGroups: []string{"networking.k8s.io"},
			Resources: []string{"networkpolicies"},
			Verbs:     []string{"get", "list", "watch"},
		},
		{
			APIGroups: []string{""},
			Resources: []string{"componentstatuses", "endpoints", "namespaces", "nodes", "pods", "services"},
			Verbs:     []string{"get", "list", "watch"},
		},
		{
			APIGroups: []string{"apiextensions.k8s.io"},
			Resources: []string{"customresourcedefinitions"},
			Verbs:     []string{"get", "list", "watch"},
		},
		{
			APIGroups: []string{"cilium.io"},
			Resources: []string{"*"},
			Verbs:     []string{"get", "list", "watch"},
		},
	},
}

func (k *K8sHubble) generateHubbleUIService() *corev1.Service {
	s := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:   defaults.HubbleUIServiceName,
			Labels: defaults.HubbleUIDeploymentLabels,
		},
		Spec: corev1.ServiceSpec{
			Type: corev1.ServiceTypeClusterIP,
			Ports: []corev1.ServicePort{
				{
					Port:       int32(80),
					TargetPort: hubbleUIPortIntstr,
				},
			},
			Selector: defaults.HubbleUIDeploymentLabels,
		},
	}
	return s
}

func (k *K8sHubble) generateHubbleUIConfigMap() *corev1.ConfigMap {
	return &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name: defaults.HubbleUIConfigMapName,
		},
		Data: map[string]string{
			"envoy.yaml": `static_resources:
  listeners:
    - name: listener_hubble_ui
      address:
        socket_address:
          address: 0.0.0.0
          port_value: 8081
      filter_chains:
        - filters:
            - name: envoy.filters.network.http_connection_manager
              config:
                codec_type: auto
                stat_prefix: ingress_http
                route_config:
                  name: local_route
                  virtual_hosts:
                    - name: local_service
                      domains: ['*']
                      routes:
                        - match:
                            prefix: '/api/'
                          route:
                            cluster: backend
                            max_grpc_timeout: 0s
                            prefix_rewrite: '/'
                        - match:
                            prefix: '/'
                          route:
                            cluster: frontend
                      cors:
                        allow_origin_string_match:
                          - prefix: '*'
                        allow_methods: GET, PUT, DELETE, POST, OPTIONS
                        allow_headers: keep-alive,user-agent,cache-control,content-type,content-transfer-encoding,x-accept-content-transfer-encoding,x-accept-response-streaming,x-user-agent,x-grpc-web,grpc-timeout
                        max_age: '1728000'
                        expose_headers: grpc-status,grpc-message
                http_filters:
                  - name: envoy.filters.http.grpc_web
                  - name: envoy.filters.http.cors
                  - name: envoy.filters.http.router
  clusters:
    - name: frontend
      connect_timeout: 0.25s
      type: strict_dns
      lb_policy: round_robin
      hosts:
        - socket_address:
            address: 127.0.0.1
            port_value: 8080
    - name: backend
      connect_timeout: 0.25s
      type: logical_dns
      lb_policy: round_robin
      http2_protocol_options: {}
      hosts:
        - socket_address:
            address: 127.0.0.1
            port_value: 8090`,
		},
	}
}

func (k *K8sHubble) generateHubbleUIDeployment() *appsv1.Deployment {
	d := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:   defaults.HubbleUIDeploymentName,
			Labels: defaults.HubbleUIDeploymentLabels,
		},
		Spec: appsv1.DeploymentSpec{
			Replicas: &hubbleUIReplicas,
			Selector: &metav1.LabelSelector{
				MatchLabels: defaults.HubbleUIDeploymentLabels,
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
					Name:   defaults.HubbleUIDeploymentName,
					Labels: defaults.HubbleUIDeploymentLabels,
				},
				Spec: corev1.PodSpec{
					RestartPolicy:      corev1.RestartPolicyAlways,
					ServiceAccountName: defaults.HubbleUIServiceAccountName,
					SecurityContext: &corev1.PodSecurityContext{
						RunAsUser: &hubbleUIUser,
					},
					Containers: []corev1.Container{
						{
							Name:            "frontend",
							Image:           "quay.io/cilium/hubble-ui:latest",
							ImagePullPolicy: corev1.PullIfNotPresent,
							Ports: []corev1.ContainerPort{
								{
									Name:          "http",
									ContainerPort: 8080,
								},
							},
						},
						{
							Name:            "backend",
							Image:           "quay.io/cilium/hubble-ui-backend:latest",
							ImagePullPolicy: corev1.PullIfNotPresent,
							Env: []corev1.EnvVar{
								{Name: "EVENTS_SERVER_PORT", Value: "8090"},
								{Name: "FLOWS_API_ADDR", Value: "hubble-relay:80"},
							},
							Ports: []corev1.ContainerPort{
								{
									Name:          "grpc",
									ContainerPort: 8090,
								},
							},
						},
						{
							Name:            "proxy",
							Image:           "docker.io/envoyproxy/envoy:v1.14.5",
							ImagePullPolicy: corev1.PullIfNotPresent,
							Command:         []string{"envoy"},
							Args:            []string{"-c", "/etc/envoy.yaml", "-l", "info"},
							Env: []corev1.EnvVar{
								{Name: "EVENTS_SERVER_PORT", Value: "8090"},
								{Name: "FLOWS_API_ADDR", Value: "hubble-relay:80"},
							},
							Ports: []corev1.ContainerPort{
								{
									Name:          "http",
									ContainerPort: 8081,
								},
							},
							VolumeMounts: []corev1.VolumeMount{
								{
									Name:      "hubble-ui-envoy-yaml",
									MountPath: "/etc/envoy.yaml",
									SubPath:   "envoy.yaml",
								},
							},
						},
					},
					Volumes: []corev1.Volume{
						{
							Name: "hubble-ui-envoy-yaml",
							VolumeSource: corev1.VolumeSource{
								ConfigMap: &corev1.ConfigMapVolumeSource{
									LocalObjectReference: corev1.LocalObjectReference{
										Name: defaults.HubbleUIConfigMapName,
									},
								},
							},
						},
					},
				},
			},
		},
	}
	return d
}

func (k *K8sHubble) disableUI(ctx context.Context) error {
	k.Log("🔥 Deleting Hubble UI...")
	k.client.DeleteService(ctx, k.params.Namespace, defaults.HubbleUIServiceName, metav1.DeleteOptions{})
	k.client.DeleteDeployment(ctx, k.params.Namespace, defaults.HubbleUIDeploymentName, metav1.DeleteOptions{})
	k.client.DeleteClusterRoleBinding(ctx, defaults.HubbleUIClusterRoleName, metav1.DeleteOptions{})
	k.client.DeleteClusterRole(ctx, defaults.HubbleUIClusterRoleName, metav1.DeleteOptions{})
	k.client.DeleteServiceAccount(ctx, k.params.Namespace, defaults.HubbleUIServiceAccountName, metav1.DeleteOptions{})
	k.client.DeleteConfigMap(ctx, k.params.Namespace, defaults.HubbleUIConfigMapName, metav1.DeleteOptions{})

	return nil
}

func (k *K8sHubble) enableUI(ctx context.Context) error {
	_, err := k.client.GetDeployment(ctx, k.params.Namespace, defaults.HubbleUIDeploymentName, metav1.GetOptions{})
	if err == nil {
		k.Log("✅ Hubble UI is already deployed")
		return nil
	}

	k.Log("✨ Deploying Hubble UI...")
	if _, err := k.client.CreateConfigMap(ctx, k.params.Namespace, k.generateHubbleUIConfigMap(), metav1.CreateOptions{}); err != nil {
		return err
	}

	if _, err := k.client.CreateServiceAccount(ctx, k.params.Namespace, k8s.NewServiceAccount(defaults.HubbleUIServiceAccountName), metav1.CreateOptions{}); err != nil {
		return err
	}

	if _, err := k.client.CreateClusterRole(ctx, hubbleUIClusterRole, metav1.CreateOptions{}); err != nil {
		return err
	}

	if _, err := k.client.CreateClusterRoleBinding(ctx, k8s.NewClusterRoleBinding(defaults.HubbleUIClusterRoleName, k.params.Namespace, defaults.HubbleUIServiceAccountName), metav1.CreateOptions{}); err != nil {
		return err
	}

	if _, err := k.client.CreateDeployment(ctx, k.params.Namespace, k.generateHubbleUIDeployment(), metav1.CreateOptions{}); err != nil {
		return err
	}

	if _, err := k.client.CreateService(ctx, k.params.Namespace, k.generateHubbleUIService(), metav1.CreateOptions{}); err != nil {
		return err
	}

	return nil
}

func (k *K8sHubble) UIPortForwardCommand(ctx context.Context) error {
	cmd := "kubectl"
	args := []string{
		"port-forward",
		"-n", k.params.Namespace,
		"svc/hubble-ui",
		"--address", "0.0.0.0",
		"--address", "::",
		fmt.Sprintf("%d:80", k.params.UIPortForward)}

	c := exec.Command(cmd, args...)
	c.Stdout = k.params.Writer
	c.Stderr = k.params.Writer

	go func() {
		time.Sleep(5 * time.Second)
		url := fmt.Sprintf("http://localhost:%d", k.params.UIPortForward)

		c := exec.Command("open", url)
		c.Stdout = k.params.Writer
		c.Stderr = k.params.Writer
		if err := c.Run(); err != nil {
			k.Log("⚠️  Unable to execute command %s %v: %s", cmd, args, err)
			k.Log("ℹ️  Opening the following URL in your browser:" + url)
		}
	}()

	if err := c.Run(); err != nil {
		return fmt.Errorf("unable to execute command %s %v: %s", cmd, args, err)
	}

	return nil
}
