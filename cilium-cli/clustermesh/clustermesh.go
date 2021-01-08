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

package clustermesh

import (
	"context"
	"fmt"
	"io"

	"github.com/cilium/cilium-cli/defaults"
	"github.com/cilium/cilium-cli/internal/certs"
	"github.com/cilium/cilium-cli/internal/k8s"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
)

const (
	configNameClusterID   = "cluster-id"
	configNameClusterName = "cluster-name"
)

var (
	replicas                 = int32(1)
	deploymentMaxSurge       = intstr.FromInt(1)
	deploymentMaxUnavailable = intstr.FromInt(1)
	secretDefaultMode        = int32(420)
)

var clusterRole = &rbacv1.ClusterRole{
	ObjectMeta: metav1.ObjectMeta{
		Name: defaults.ClusterMeshClusterRoleName,
	},
	Rules: []rbacv1.PolicyRule{
		{
			APIGroups: []string{"discovery.k8s.io"},
			Resources: []string{"endpointslices"},
			Verbs:     []string{"get", "list", "watch"},
		},
		{
			APIGroups: []string{""},
			Resources: []string{"namespaces", "services", "endpoints"},
			Verbs:     []string{"get", "list", "watch"},
		},
		{
			APIGroups: []string{"apiextensions.k8s.io"},
			Resources: []string{"customresourcedefinitions"},
			Verbs:     []string{"list"},
		},
		{
			APIGroups: []string{"cilium.io"},
			Resources: []string{
				"ciliumnodes",
				"ciliumnodes/status",
				"ciliumexternalworkloads",
				"ciliumexternalworkloads/status",
				"ciliumidentities",
				"ciliumidentities/status",
				"ciliumendpoints",
				"ciliumendpoints/status",
			},
			Verbs: []string{"*"},
		},
	},
}

var service = &corev1.Service{
	ObjectMeta: metav1.ObjectMeta{
		Name:   defaults.ClusterMeshServiceName,
		Labels: defaults.ClusterMeshDeploymentLabels,
	},
	Spec: corev1.ServiceSpec{
		Type: corev1.ServiceTypeClusterIP,
		Ports: []corev1.ServicePort{
			{Port: int32(2379)},
		},
		Selector: defaults.ClusterMeshDeploymentLabels,
	},
}

var initContainerArgs = []string{`rm -rf /var/run/etcd/*;
export ETCDCTL_API=3;
/usr/local/bin/etcd --data-dir=/var/run/etcd --name=clustermesh-apiserver --listen-client-urls=http://127.0.0.1:2379 --advertise-client-urls=http://127.0.0.1:2379 --initial-cluster-token=clustermesh-apiserver --initial-cluster-state=new --auto-compaction-retention=1 &
export rootpw=` + "`" + `head /dev/urandom | tr -dc A-Za-z0-9 | head -c 16` + "`" + `;
echo $rootpw | etcdctl --interactive=false user add root;
etcdctl user grant-role root root;
export vmpw=` + "`" + `head /dev/urandom | tr -dc A-Za-z0-9 | head -c 16` + "`" + `;
echo $vmpw | etcdctl --interactive=false user add externalworkload;
etcdctl role add externalworkload;
etcdctl role grant-permission externalworkload --from-key read '';
etcdctl role grant-permission externalworkload readwrite --prefix cilium/state/noderegister/v1/;
etcdctl role grant-permission externalworkload readwrite --prefix cilium/.initlock/;
etcdctl user grant-role externalworkload externalworkload;
export remotepw=` + "`" + `head /dev/urandom | tr -dc A-Za-z0-9 | head -c 16` + "`" + `;
echo $remotepw | etcdctl --interactive=false user add remote;
etcdctl role add remote;
etcdctl role grant-permission remote --from-key read '';
etcdctl user grant-role remote remote;
etcdctl auth enable;
exit`}

var deployment = &appsv1.Deployment{
	ObjectMeta: metav1.ObjectMeta{
		Name:   defaults.ClusterMeshDeploymentName,
		Labels: defaults.ClusterMeshDeploymentLabels,
	},
	Spec: appsv1.DeploymentSpec{
		Replicas: &replicas,
		Selector: &metav1.LabelSelector{
			MatchLabels: defaults.ClusterMeshDeploymentLabels,
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
				Name:   defaults.ClusterMeshDeploymentName,
				Labels: defaults.ClusterMeshDeploymentLabels,
			},
			Spec: corev1.PodSpec{
				RestartPolicy:      corev1.RestartPolicyAlways,
				ServiceAccountName: defaults.ClusterMeshServiceAccountName,
				Containers: []corev1.Container{
					{
						Name:    "etcd",
						Command: []string{"/usr/local/bin/etcd"},
						Args: []string{
							"--data-dir=/var/run/etcd",
							"--name=clustermesh-apiserver",
							"--client-cert-auth",
							"--trusted-ca-file=/var/lib/etcd-secrets/ca.crt",
							"--cert-file=/var/lib/etcd-secrets/tls.crt",
							"--key-file=/var/lib/etcd-secrets/tls.key",
							"--listen-client-urls=https://127.0.0.1:2379,https://$(HOSTNAME_IP):2379",
							"--advertise-client-urls=https://$(HOSTNAME_IP):2379",
							"--initial-cluster-token=clustermesh-apiserver",
							"--auto-compaction-retention=1",
						},
						Image:           "quay.io/coreos/etcd:v3.4.13",
						ImagePullPolicy: corev1.PullIfNotPresent,
						Env: []corev1.EnvVar{
							{
								Name:  "ETCDCTL_API",
								Value: "3",
							},
							{
								Name: "HOSTNAME_IP",
								ValueFrom: &corev1.EnvVarSource{
									FieldRef: &corev1.ObjectFieldSelector{
										FieldPath: "status.podIP",
									},
								},
							},
						},
						VolumeMounts: []corev1.VolumeMount{
							{
								Name:      "etcd-server-secrets",
								MountPath: "/var/lib/etcd-secrets",
								ReadOnly:  true,
							},
							{
								Name:      "etcd-data-dir",
								MountPath: "/var/run/etcd",
							},
						},
					},
					{
						Name:    "apiserver",
						Command: []string{"/usr/bin/clustermesh-apiserver"},
						Args: []string{
							"--cluster-name=$(CLUSTER_NAME)",
							"--kvstore-opt",
							"etcd.config=/var/lib/cilium/etcd-config.yaml",
						},
						Image:           "quay.io/cilium/clustermesh-apiserver:latest",
						ImagePullPolicy: corev1.PullIfNotPresent,
						Env: []corev1.EnvVar{
							{
								Name: "CLUSTER_NAME",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: defaults.ConfigMapName,
										},
										Key: configNameClusterName,
									},
								},
							},
							{
								Name: "CLUSTER_ID",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: defaults.ConfigMapName,
										},
										Key: configNameClusterID,
									},
								},
							},
							{
								Name: "IDENTITY_ALLOCATION_MODE",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: defaults.ConfigMapName,
										},
										Key: "identity-allocation-mode",
									},
								},
							},
						},
						VolumeMounts: []corev1.VolumeMount{
							{
								Name:      "etcd-admin-client",
								MountPath: "/var/lib/cilium/etcd-secrets",
								ReadOnly:  true,
							},
						},
					},
				},
				InitContainers: []corev1.Container{
					{
						Name:            "etcd-init",
						Command:         []string{"/bin/sh", "-c"},
						Args:            initContainerArgs,
						Image:           "quay.io/coreos/etcd:v3.4.13",
						ImagePullPolicy: corev1.PullIfNotPresent,
						Env: []corev1.EnvVar{
							{
								Name:  "ETCDCTL_API",
								Value: "3",
							},
							{
								Name: "HOSTNAME_IP",
								ValueFrom: &corev1.EnvVarSource{
									FieldRef: &corev1.ObjectFieldSelector{
										FieldPath: "status.podIP",
									},
								},
							},
						},
						VolumeMounts: []corev1.VolumeMount{
							{
								Name:      "etcd-data-dir",
								MountPath: "etcd-data-dir",
							},
						},
					},
				},
				Volumes: []corev1.Volume{
					{
						Name: "etcd-data-dir",
						VolumeSource: corev1.VolumeSource{
							EmptyDir: &corev1.EmptyDirVolumeSource{},
						},
					},
					{
						Name: "etcd-server-secrets",
						VolumeSource: corev1.VolumeSource{
							Projected: &corev1.ProjectedVolumeSource{
								DefaultMode: &secretDefaultMode,
								Sources: []corev1.VolumeProjection{
									{
										Secret: &corev1.SecretProjection{
											LocalObjectReference: corev1.LocalObjectReference{
												Name: defaults.CASecretName,
											},
											Items: []corev1.KeyToPath{
												{
													Key:  defaults.CASecretCertName,
													Path: "ca.crt",
												},
											},
										},
									},
									{
										Secret: &corev1.SecretProjection{
											LocalObjectReference: corev1.LocalObjectReference{
												Name: defaults.ClusterMeshServerSecretName,
											},
										},
									},
								},
							},
						},
					},
					{
						Name: "etcd-admin-client",
						VolumeSource: corev1.VolumeSource{
							Projected: &corev1.ProjectedVolumeSource{
								DefaultMode: &secretDefaultMode,
								Sources: []corev1.VolumeProjection{
									{
										Secret: &corev1.SecretProjection{
											LocalObjectReference: corev1.LocalObjectReference{
												Name: defaults.CASecretName,
											},
											Items: []corev1.KeyToPath{
												{
													Key:  defaults.CASecretCertName,
													Path: "ca.crt",
												},
											},
										},
									},
									{
										Secret: &corev1.SecretProjection{
											LocalObjectReference: corev1.LocalObjectReference{
												Name: defaults.ClusterMeshAdminSecretName,
											},
										},
									},
								},
							},
						},
					},
				},
			},
		},
	},
}

type k8sClusterMeshImplementation interface {
	CreateSecret(ctx context.Context, namespace string, secret *corev1.Secret, opts metav1.CreateOptions) (*corev1.Secret, error)
	DeleteSecret(ctx context.Context, namespace, name string, opts metav1.DeleteOptions) error
	GetSecret(ctx context.Context, namespace, name string, opts metav1.GetOptions) (*corev1.Secret, error)
	CreateServiceAccount(ctx context.Context, namespace string, account *corev1.ServiceAccount, opts metav1.CreateOptions) (*corev1.ServiceAccount, error)
	DeleteServiceAccount(ctx context.Context, namespace, name string, opts metav1.DeleteOptions) error
	CreateClusterRole(ctx context.Context, role *rbacv1.ClusterRole, opts metav1.CreateOptions) (*rbacv1.ClusterRole, error)
	DeleteClusterRole(ctx context.Context, name string, opts metav1.DeleteOptions) error
	CreateClusterRoleBinding(ctx context.Context, role *rbacv1.ClusterRoleBinding, opts metav1.CreateOptions) (*rbacv1.ClusterRoleBinding, error)
	DeleteClusterRoleBinding(ctx context.Context, name string, opts metav1.DeleteOptions) error
	GetConfigMap(ctx context.Context, namespace, name string, opts metav1.GetOptions) (*corev1.ConfigMap, error)
	CreateDeployment(ctx context.Context, namespace string, deployment *appsv1.Deployment, opts metav1.CreateOptions) (*appsv1.Deployment, error)
	GetDeployment(ctx context.Context, namespace, name string, opts metav1.GetOptions) (*appsv1.Deployment, error)
	DeleteDeployment(ctx context.Context, namespace, name string, opts metav1.DeleteOptions) error
	CreateService(ctx context.Context, namespace string, service *corev1.Service, opts metav1.CreateOptions) (*corev1.Service, error)
	DeleteService(ctx context.Context, namespace, name string, opts metav1.DeleteOptions) error
	GetService(ctx context.Context, namespace, name string, opts metav1.GetOptions) (*corev1.Service, error)
}

type K8sClusterMesh struct {
	client      k8sClusterMeshImplementation
	certManager *certs.CertManager
	params      Parameters
}

type Parameters struct {
	Namespace   string
	ServiceType string
	Writer      io.Writer
}

func NewK8sClusterMesh(client k8sClusterMeshImplementation, p Parameters) *K8sClusterMesh {
	return &K8sClusterMesh{
		client:      client,
		params:      p,
		certManager: certs.NewCertManager(client, certs.Parameters{Namespace: p.Namespace}),
	}
}

func (k *K8sClusterMesh) Log(format string, a ...interface{}) {
	fmt.Fprintf(k.params.Writer, format+"\n", a...)
}

func (k *K8sClusterMesh) Validate(ctx context.Context) error {
	var failures int
	k.Log("✨ Validating cluster configuration...")

	cm, err := k.client.GetConfigMap(ctx, k.params.Namespace, defaults.ConfigMapName, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("unable to retrieve ConfigMap %q: %w", defaults.ConfigMapName, err)
	}

	if cm.Data == nil {
		return fmt.Errorf("ConfigMap %q does not contain any configuration", defaults.ConfigMapName)
	}

	clusterID, ok := cm.Data[configNameClusterID]
	if !ok {
		k.Log("❌ Cluster ID (%q) is not set", configNameClusterID)
		failures++
	}

	if clusterID == "" || clusterID == "0" {
		k.Log("❌ Cluster ID (%q) must be set to a value > 0", configNameClusterID)
		failures++
	}

	clusterName, ok := cm.Data[configNameClusterName]
	if !ok {
		k.Log("❌ Cluster name (%q) is not set", configNameClusterName)
		failures++
	}

	if clusterName == "" || clusterName == "default" {
		k.Log("❌ Cluster name (%q) must be set to a value other than \"default\"", configNameClusterName)
		failures++
	}

	if failures > 0 {
		return fmt.Errorf("%d validation errors", failures)
	}

	k.Log("✅ Valid cluster identification found: name=%q id=%q", clusterName, clusterID)

	return nil

}

func (k *K8sClusterMesh) Disable(ctx context.Context) error {
	k.Log("🔥 Deleting clustermesh-apiserver...")
	k.client.DeleteService(ctx, k.params.Namespace, defaults.ClusterMeshServiceName, metav1.DeleteOptions{})
	k.client.DeleteDeployment(ctx, k.params.Namespace, defaults.ClusterMeshDeploymentName, metav1.DeleteOptions{})
	k.client.DeleteClusterRoleBinding(ctx, defaults.ClusterMeshClusterRoleName, metav1.DeleteOptions{})
	k.client.DeleteClusterRole(ctx, defaults.ClusterMeshClusterRoleName, metav1.DeleteOptions{})
	k.client.DeleteServiceAccount(ctx, k.params.Namespace, defaults.ClusterMeshServiceAccountName, metav1.DeleteOptions{})

	k.deleteCertificates(ctx)

	return nil
}

func (p Parameters) validateForEnable() error {
	switch corev1.ServiceType(p.ServiceType) {
	case corev1.ServiceTypeClusterIP, corev1.ServiceTypeNodePort, corev1.ServiceTypeLoadBalancer, corev1.ServiceTypeExternalName:
	default:
		return fmt.Errorf("unknown service type %q", p.ServiceType)
	}

	return nil
}

func (k *K8sClusterMesh) Enable(ctx context.Context) error {
	if err := k.params.validateForEnable(); err != nil {
		return err
	}

	if err := k.Validate(ctx); err != nil {
		return err
	}

	_, err := k.client.GetDeployment(ctx, k.params.Namespace, "clustermesh-apiserver", metav1.GetOptions{})
	if err == nil {
		k.Log("✅ ClusterMesh is already enabled")
		return nil
	}

	if err := k.installCertificates(ctx); err != nil {
		return err
	}

	k.Log("✨ Deploying clustermesh-apiserver...")
	if _, err := k.client.CreateServiceAccount(ctx, k.params.Namespace, k8s.NewServiceAccount(defaults.ClusterMeshServiceAccountName), metav1.CreateOptions{}); err != nil {
		return err
	}

	if _, err := k.client.CreateClusterRole(ctx, clusterRole, metav1.CreateOptions{}); err != nil {
		return err
	}

	if _, err := k.client.CreateClusterRoleBinding(ctx, k8s.NewClusterRoleBinding(defaults.ClusterMeshClusterRoleName, k.params.Namespace, defaults.ClusterMeshServiceAccountName), metav1.CreateOptions{}); err != nil {
		return err
	}

	if _, err := k.client.CreateDeployment(ctx, k.params.Namespace, deployment, metav1.CreateOptions{}); err != nil {
		return err
	}

	service.Spec.Type = corev1.ServiceType(k.params.ServiceType)
	if _, err := k.client.CreateService(ctx, k.params.Namespace, service, metav1.CreateOptions{}); err != nil {
		return err
	}

	return nil
}

func (k *K8sClusterMesh) GetAccessToken(ctx context.Context) error {
	if _, err := k.client.GetService(ctx, k.params.Namespace, defaults.ClusterMeshServiceName, metav1.GetOptions{}); err != nil {
		return err
	}

	return nil
}
