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
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/cilium/cilium-cli/defaults"
	"github.com/cilium/cilium-cli/internal/certs"
	"github.com/cilium/cilium-cli/internal/k8s"
	"github.com/cilium/cilium-cli/internal/utils"
	"github.com/cilium/cilium-cli/status"

	"github.com/cilium/cilium/api/v1/models"
	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
)

const (
	configNameClusterID   = "cluster-id"
	configNameClusterName = "cluster-name"

	caSuffix   = ".etcd-client-ca.crt"
	keySuffix  = ".etcd-client.key"
	certSuffix = ".etcd-client.crt"
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

func (k *K8sClusterMesh) generateService() (*corev1.Service, error) {
	svc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:        defaults.ClusterMeshServiceName,
			Labels:      defaults.ClusterMeshDeploymentLabels,
			Annotations: map[string]string{},
		},
		Spec: corev1.ServiceSpec{
			Type: corev1.ServiceTypeClusterIP,
			Ports: []corev1.ServicePort{
				{Port: int32(2379)},
			},
			Selector: defaults.ClusterMeshDeploymentLabels,
		},
	}

	if k.params.ServiceType != "" {
		if k.params.ServiceType == "NodePort" {
			k.Log("⚠️  Using service type NodePort may fail when nodes are removed from the cluster!")
		}
		svc.Spec.Type = corev1.ServiceType(k.params.ServiceType)
	} else {
		switch k.flavor.Kind {
		case k8s.KindGKE:
			k.Log("🔮 Auto-exposing service within GCP VPC (cloud.google.com/load-balancer-type=Internal)")
			svc.Spec.Type = corev1.ServiceTypeLoadBalancer
			svc.ObjectMeta.Annotations["cloud.google.com/load-balancer-type"] = "Internal"
			// if all the clusters are in the same region the next annotation can be removed
			svc.ObjectMeta.Annotations["networking.gke.io/internal-load-balancer-allow-global-access"] = "true"
		case k8s.KindAKS:
			k.Log("🔮 Auto-exposing service within Azure VPC (service.beta.kubernetes.io/azure-load-balancer-internal)")
			svc.Spec.Type = corev1.ServiceTypeLoadBalancer
			svc.ObjectMeta.Annotations["service.beta.kubernetes.io/azure-load-balancer-internal"] = "true"
		case k8s.KindEKS:
			k.Log("🔮 Auto-exposing service within AWS VPC (service.beta.kubernetes.io/aws-load-balancer-internal: 0.0.0.0/0")
			svc.Spec.Type = corev1.ServiceTypeLoadBalancer
			svc.ObjectMeta.Annotations["service.beta.kubernetes.io/aws-load-balancer-internal"] = "0.0.0.0/0"
		default:
			return nil, fmt.Errorf("cannot auto-detect service type, please specify using '--service-type' option")
		}
	}

	return svc, nil
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

func (k *K8sClusterMesh) apiserverImage() string {
	if k.params.ApiserverImage != "" {
		return k.params.ApiserverImage
	}

	return defaults.ClusterMeshApiserverImage
}

func (k *K8sClusterMesh) generateDeployment() *appsv1.Deployment {
	deployment := &appsv1.Deployment{
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
								"--cluster-name=" + k.clusterName,
								"--cluster-id=" + k.clusterID,
								"--kvstore-opt",
								"etcd.config=/var/lib/cilium/etcd-config.yaml",
							},
							Image:           k.apiserverImage(),
							ImagePullPolicy: corev1.PullIfNotPresent,
							Env: []corev1.EnvVar{
								{
									Name: "CILIUM_CLUSTER_NAME",
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
									Name: "CILIUM_CLUSTER_ID",
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
									Name: "CILIUM_IDENTITY_ALLOCATION_MODE",
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
	return deployment
}

type k8sClusterMeshImplementation interface {
	CreateSecret(ctx context.Context, namespace string, secret *corev1.Secret, opts metav1.CreateOptions) (*corev1.Secret, error)
	PatchSecret(ctx context.Context, namespace, name string, pt types.PatchType, data []byte, opts metav1.PatchOptions) (*corev1.Secret, error)
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
	PatchDaemonSet(ctx context.Context, namespace, name string, pt types.PatchType, data []byte, opts metav1.PatchOptions) (*appsv1.DaemonSet, error)
	GetDaemonSet(ctx context.Context, namespace, name string, options metav1.GetOptions) (*appsv1.DaemonSet, error)
	ListNodes(ctx context.Context, options metav1.ListOptions) (*corev1.NodeList, error)
	ListPods(ctx context.Context, namespace string, options metav1.ListOptions) (*corev1.PodList, error)
	AutodetectFlavor(ctx context.Context) (k8s.Flavor, error)
	CiliumStatus(ctx context.Context, namespace, pod string) (*models.StatusResponse, error)
	ClusterName() string
	ListCiliumExternalWorkloads(ctx context.Context, opts metav1.ListOptions) (*ciliumv2.CiliumExternalWorkloadList, error)
	GetCiliumExternalWorkload(ctx context.Context, name string, opts metav1.GetOptions) (*ciliumv2.CiliumExternalWorkload, error)
	CreateCiliumExternalWorkload(ctx context.Context, cew *ciliumv2.CiliumExternalWorkload, opts metav1.CreateOptions) (*ciliumv2.CiliumExternalWorkload, error)
	DeleteCiliumExternalWorkload(ctx context.Context, name string, opts metav1.DeleteOptions) error
}

type K8sClusterMesh struct {
	client          k8sClusterMeshImplementation
	certManager     *certs.CertManager
	statusCollector *status.K8sStatusCollector
	flavor          k8s.Flavor
	params          Parameters
	clusterName     string
	clusterID       string
}

type Parameters struct {
	Namespace            string
	ServiceType          string
	DestinationContext   string
	Wait                 bool
	WaitDuration         time.Duration
	DestinationEndpoints []string
	SourceEndpoints      []string
	SkipServiceCheck     bool
	ApiserverImage       string
	CreateCA             bool
	Writer               io.Writer
	Labels               map[string]string
	IPv4AllocCIDR        string
	IPv6AllocCIDR        string
	All                  bool
}

func (p Parameters) waitTimeout() time.Duration {
	if p.WaitDuration != time.Duration(0) {
		return p.WaitDuration
	}

	return time.Minute * 15
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

func (k *K8sClusterMesh) GetClusterConfig(ctx context.Context) error {
	f, err := k.client.AutodetectFlavor(ctx)
	if err != nil {
		return err
	}
	k.flavor = f

	cm, err := k.client.GetConfigMap(ctx, k.params.Namespace, defaults.ConfigMapName, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("unable to retrieve ConfigMap %q: %w", defaults.ConfigMapName, err)
	}

	clusterID := cm.Data[configNameClusterID]
	if clusterID == "" || clusterID == "0" {
		clusterID = "0"
	}
	k.clusterID = clusterID

	clusterName := cm.Data[configNameClusterName]
	if clusterName == "" || clusterName == "default" {
		clusterName = "default"
	}
	k.clusterName = clusterName

	return nil
}

func (k *K8sClusterMesh) Disable(ctx context.Context) error {
	k.Log("🔥 Deleting clustermesh-apiserver...")
	k.client.DeleteService(ctx, k.params.Namespace, defaults.ClusterMeshServiceName, metav1.DeleteOptions{})
	k.client.DeleteDeployment(ctx, k.params.Namespace, defaults.ClusterMeshDeploymentName, metav1.DeleteOptions{})
	k.client.DeleteClusterRoleBinding(ctx, defaults.ClusterMeshClusterRoleName, metav1.DeleteOptions{})
	k.client.DeleteClusterRole(ctx, defaults.ClusterMeshClusterRoleName, metav1.DeleteOptions{})
	k.client.DeleteServiceAccount(ctx, k.params.Namespace, defaults.ClusterMeshServiceAccountName, metav1.DeleteOptions{})
	k.client.DeleteSecret(ctx, k.params.Namespace, defaults.ClusterMeshSecretName, metav1.DeleteOptions{})

	k.deleteCertificates(ctx)

	return nil
}

func (p Parameters) validateForEnable() error {
	switch corev1.ServiceType(p.ServiceType) {
	case corev1.ServiceTypeClusterIP:
	case corev1.ServiceTypeNodePort:
	case corev1.ServiceTypeLoadBalancer:
	case corev1.ServiceTypeExternalName:
	case "":
	default:
		return fmt.Errorf("unknown service type %q", p.ServiceType)
	}

	return nil
}

func (k *K8sClusterMesh) Enable(ctx context.Context) error {
	if err := k.params.validateForEnable(); err != nil {
		return err
	}

	if err := k.GetClusterConfig(ctx); err != nil {
		return err
	}

	svc, err := k.generateService()
	if err != nil {
		return err
	}

	_, err = k.client.GetDeployment(ctx, k.params.Namespace, "clustermesh-apiserver", metav1.GetOptions{})
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

	if _, err := k.client.CreateDeployment(ctx, k.params.Namespace, k.generateDeployment(), metav1.CreateOptions{}); err != nil {
		return err
	}

	if _, err := k.client.CreateService(ctx, k.params.Namespace, svc, metav1.CreateOptions{}); err != nil {
		return err
	}

	return nil
}

type accessInformation struct {
	ServiceIPs           []string
	ServicePort          int
	ClusterID            string
	ClusterName          string
	CA                   []byte
	ClientCert           []byte
	ClientKey            []byte
	ExternalWorkloadCert []byte
	ExternalWorkloadKey  []byte
}

func (ai *accessInformation) etcdConfiguration() string {
	cfg := "endpoints:\n"
	cfg += "- https://" + ai.ClusterName + ".mesh.cilium.io:" + fmt.Sprintf("%d", ai.ServicePort) + "\n"
	cfg += "trusted-ca-file: /var/lib/cilium/clustermesh/" + ai.ClusterName + caSuffix + "\n"
	cfg += "key-file: /var/lib/cilium/clustermesh/" + ai.ClusterName + keySuffix + "\n"
	cfg += "cert-file: /var/lib/cilium/clustermesh/" + ai.ClusterName + certSuffix + "\n"

	return cfg
}

func (k *K8sClusterMesh) extractAccessInformation(ctx context.Context, client k8sClusterMeshImplementation, endpoints []string, verbose bool) (*accessInformation, error) {
	cm, err := client.GetConfigMap(ctx, k.params.Namespace, defaults.ConfigMapName, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("unable to retrieve ConfigMap %q: %w", defaults.ConfigMapName, err)
	}

	if _, ok := cm.Data[configNameClusterName]; !ok {
		return nil, fmt.Errorf("%s is not set in ConfigMap %q", configNameClusterName, defaults.ConfigMapName)
	}

	clusterID := cm.Data[configNameClusterID]
	clusterName := cm.Data[configNameClusterName]

	if verbose {
		k.Log("✨ Extracting access information of cluster %s...", clusterName)
	}
	svc, err := client.GetService(ctx, k.params.Namespace, defaults.ClusterMeshServiceName, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("unable to get clustermesh service %q: %w", defaults.ClusterMeshServiceName, err)
	}

	if verbose {
		k.Log("🔑 Extracting secrets from cluster %s...", clusterName)
	}
	caSecret, err := client.GetSecret(ctx, k.params.Namespace, defaults.CASecretName, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("unable to get secret %q to retrieve CA: %s", defaults.CASecretName, err)
	}

	caCert, ok := caSecret.Data[defaults.CASecretCertName]
	if !ok {
		return nil, fmt.Errorf("secret %q does not contain CA cert %q", defaults.CASecretName, defaults.CASecretCertName)
	}

	meshSecret, err := client.GetSecret(ctx, k.params.Namespace, defaults.ClusterMeshClientSecretName, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("unable to get secret %q to access clustermesh service: %s", defaults.ClusterMeshClientSecretName, err)
	}

	clientKey, ok := meshSecret.Data[defaults.ClusterMeshClientSecretKeyName]
	if !ok {
		return nil, fmt.Errorf("secret %q does not contain key %q", defaults.ClusterMeshClientSecretName, defaults.ClusterMeshClientSecretKeyName)
	}

	clientCert, ok := meshSecret.Data[defaults.ClusterMeshClientSecretCertName]
	if !ok {
		return nil, fmt.Errorf("secret %q does not contain key %q", defaults.ClusterMeshClientSecretName, defaults.ClusterMeshClientSecretCertName)
	}

	externalWorkloadSecret, err := client.GetSecret(ctx, k.params.Namespace, defaults.ClusterMeshExternalWorkloadSecretName, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("unable to get secret %q to access clustermesh service: %s", defaults.ClusterMeshExternalWorkloadSecretName, err)
	}

	externalWorkloadKey, ok := externalWorkloadSecret.Data[defaults.ClusterMeshExternalWorkloadSecretKeyName]
	if !ok {
		return nil, fmt.Errorf("secret %q does not contain key %q", defaults.ClusterMeshExternalWorkloadSecretName, defaults.ClusterMeshExternalWorkloadSecretKeyName)
	}

	externalWorkloadCert, ok := externalWorkloadSecret.Data[defaults.ClusterMeshExternalWorkloadSecretCertName]
	if !ok {
		return nil, fmt.Errorf("secret %q does not contain key %q", defaults.ClusterMeshExternalWorkloadSecretName, defaults.ClusterMeshExternalWorkloadSecretCertName)
	}

	ai := &accessInformation{
		ClusterID:            clusterID,
		ClusterName:          clusterName,
		CA:                   caCert,
		ClientKey:            clientKey,
		ClientCert:           clientCert,
		ExternalWorkloadKey:  externalWorkloadKey,
		ExternalWorkloadCert: externalWorkloadCert,
		ServiceIPs:           []string{},
	}

	switch {
	case len(endpoints) > 0:
		for _, endpoint := range endpoints {
			ip, port, err := net.SplitHostPort(endpoint)
			if err != nil {
				return nil, fmt.Errorf("invalid endpoint %q, must be IP:PORT: %w", endpoint, err)
			}

			intPort, err := strconv.Atoi(port)
			if err != nil {
				return nil, fmt.Errorf("invalid port %q: %w", port, err)
			}

			if ai.ServicePort == 0 {
				ai.ServicePort = intPort
			} else if ai.ServicePort != intPort {
				return nil, fmt.Errorf("port mismatch (%d != %d), all endpoints must use the same port number", ai.ServicePort, intPort)
			}

			ai.ServiceIPs = append(ai.ServiceIPs, ip)
		}

	case svc.Spec.Type == corev1.ServiceTypeClusterIP:
		if len(svc.Spec.Ports) == 0 {
			return nil, fmt.Errorf("port of service could not be derived, service has no ports")
		}
		if svc.Spec.Ports[0].Port == 0 {
			return nil, fmt.Errorf("port is not set in service")
		}
		ai.ServicePort = int(svc.Spec.Ports[0].Port)

		if svc.Spec.ClusterIP == "" {
			return nil, fmt.Errorf("IP of service could not be derived, service has no ClusterIP")
		}
		ai.ServiceIPs = append(ai.ServiceIPs, svc.Spec.ClusterIP)

	case svc.Spec.Type == corev1.ServiceTypeNodePort:
		if len(svc.Spec.Ports) == 0 {
			return nil, fmt.Errorf("port of service could not be derived, service has no ports")
		}

		if svc.Spec.Ports[0].NodePort == 0 {
			return nil, fmt.Errorf("nodeport is not set in service")
		}
		ai.ServicePort = int(svc.Spec.Ports[0].NodePort)

		nodes, err := client.ListNodes(ctx, metav1.ListOptions{})
		if err != nil {
			return nil, fmt.Errorf("unable to list nodes in cluster: %w", err)
		}

		for _, node := range nodes.Items {
			nodeIP := ""
			for _, address := range node.Status.Addresses {
				switch address.Type {
				case corev1.NodeExternalIP:
					nodeIP = address.Address
				case corev1.NodeInternalIP:
					if nodeIP == "" {
						nodeIP = address.Address
					}
				}
			}

			if nodeIP != "" {
				ai.ServiceIPs = append(ai.ServiceIPs, nodeIP)

				// We can't really support multiple nodes as
				// the NodePort will be different and the
				// current use of hostAliases will lead to
				// DNS-style RR requiring all endpoints to use
				// the same port
				break
			}
		}
		k.Log("⚠️  Service type NodePort detected! Service may fail when nodes are removed from the cluster!")

	case svc.Spec.Type == corev1.ServiceTypeLoadBalancer:
		if len(svc.Spec.Ports) == 0 {
			return nil, fmt.Errorf("port of service could not be derived, service has no ports")
		}

		ai.ServicePort = int(svc.Spec.Ports[0].Port)

		for _, ingressStatus := range svc.Status.LoadBalancer.Ingress {
			if ingressStatus.Hostname != "" {
				return nil, fmt.Errorf("hostname based load-balancers are not supported yet")
			}

			if ingressStatus.IP != "" {
				ai.ServiceIPs = append(ai.ServiceIPs, ingressStatus.IP)
			}
		}
	}

	switch {
	case len(ai.ServiceIPs) > 0:
		if verbose {
			k.Log("ℹ️  Found ClusterMesh service IPs: %s", ai.ServiceIPs)
		}
	default:
		return nil, fmt.Errorf("unable to derive service IPs automatically")
	}

	return ai, nil
}

func (k *K8sClusterMesh) patchConfig(ctx context.Context, client k8sClusterMeshImplementation, ai *accessInformation) error {
	_, err := client.GetSecret(ctx, k.params.Namespace, defaults.ClusterMeshSecretName, metav1.GetOptions{})
	if err != nil {
		k.Log("🔑 Secret %s does not exist yet, creating it...", defaults.ClusterMeshSecretName)
		_, err = client.CreateSecret(ctx, k.params.Namespace, k8s.NewSecret(defaults.ClusterMeshSecretName, k.params.Namespace, map[string][]byte{}), metav1.CreateOptions{})
		if err != nil {
			return fmt.Errorf("unable to create secret: %w", err)
		}
	}

	k.Log("🔑 Patching existing secret %s...", defaults.ClusterMeshSecretName)

	etcdBase64 := `"` + ai.ClusterName + `": "` + base64.StdEncoding.EncodeToString([]byte(ai.etcdConfiguration())) + `"`
	caBase64 := `"` + ai.ClusterName + caSuffix + `": "` + base64.StdEncoding.EncodeToString(ai.CA) + `"`
	keyBase64 := `"` + ai.ClusterName + keySuffix + `": "` + base64.StdEncoding.EncodeToString(ai.ClientKey) + `"`
	certBase64 := `"` + ai.ClusterName + certSuffix + `": "` + base64.StdEncoding.EncodeToString(ai.ClientCert) + `"`

	patch := []byte(`{"data":{` + etcdBase64 + `,` + caBase64 + `,` + keyBase64 + `,` + certBase64 + `}}`)
	_, err = client.PatchSecret(ctx, k.params.Namespace, defaults.ClusterMeshSecretName, types.StrategicMergePatchType, patch, metav1.PatchOptions{})
	if err != nil {
		return fmt.Errorf("unable to patch secret %s with patch %q: %w", defaults.ClusterMeshSecretName, patch, err)
	}

	var aliases []string
	for _, ip := range ai.ServiceIPs {
		aliases = append(aliases, `{"ip":"`+ip+`", "hostnames":["`+ai.ClusterName+`.mesh.cilium.io"]}`)
	}

	patch = []byte(`{"spec":{"template":{"spec":{"hostAliases":[` + strings.Join(aliases, ",") + `]}}}}`)

	k.Log("✨ Patching DaemonSet with IP aliases %s...", defaults.ClusterMeshSecretName)
	_, err = client.PatchDaemonSet(ctx, k.params.Namespace, defaults.AgentDaemonSetName, types.StrategicMergePatchType, patch, metav1.PatchOptions{})
	if err != nil {
		return fmt.Errorf("unable to patch DaemonSet %s with patch %q: %w", defaults.AgentDaemonSetName, patch, err)
	}

	return nil
}

func (k *K8sClusterMesh) Connect(ctx context.Context) error {
	remoteCluster, err := k8s.NewClient(k.params.DestinationContext, "")
	if err != nil {
		return fmt.Errorf("unable to create Kubernetes client to access remote cluster %q: %w", k.params.DestinationContext, err)
	}

	aiRemote, err := k.extractAccessInformation(ctx, remoteCluster, k.params.DestinationEndpoints, true)
	if err != nil {
		k.Log("❌ Unable to retrieve access information of remote cluster %q: %s", remoteCluster.ClusterName(), err)
		return err
	}

	if aiRemote.ClusterName == "" || aiRemote.ClusterName == "default" || aiRemote.ClusterID == "" || aiRemote.ClusterID == "0" {
		return fmt.Errorf("remote cluster has non-unique name (%s) and/or ID (%s)", aiRemote.ClusterName, aiRemote.ClusterID)
	}

	aiLocal, err := k.extractAccessInformation(ctx, k.client, k.params.SourceEndpoints, true)
	if err != nil {
		k.Log("❌ Unable to retrieve access information of local cluster %q: %s", k.client.ClusterName(), err)
		return err
	}

	if aiLocal.ClusterName == "" || aiLocal.ClusterName == "default" || aiLocal.ClusterID == "" || aiLocal.ClusterID == "0" {
		return fmt.Errorf("local cluster has non-unique name (%s) and/or ID (%s)", aiLocal.ClusterName, aiLocal.ClusterID)
	}

	if aiRemote.ClusterName == aiLocal.ClusterName {
		return fmt.Errorf("remote and local cluster have the same, non-unique name: %s", aiLocal.ClusterName)
	}

	if aiRemote.ClusterID == aiLocal.ClusterID {
		return fmt.Errorf("remote and local cluster have the same, non-unique ID: %s", aiLocal.ClusterID)
	}

	k.Log("✨ Connecting cluster %s -> %s...", k.client.ClusterName(), remoteCluster.ClusterName())
	if err := k.patchConfig(ctx, k.client, aiRemote); err != nil {
		return err
	}
	k.Log("✨ Connecting cluster %s -> %s...", remoteCluster.ClusterName(), k.client.ClusterName())
	if err := k.patchConfig(ctx, remoteCluster, aiLocal); err != nil {
		return err
	}

	return nil
}

func (k *K8sClusterMesh) disconnectCluster(ctx context.Context, src, dst k8sClusterMeshImplementation) error {
	cm, err := dst.GetConfigMap(ctx, k.params.Namespace, defaults.ConfigMapName, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("unable to retrieve ConfigMap %q: %w", defaults.ConfigMapName, err)
	}

	if _, ok := cm.Data[configNameClusterName]; !ok {
		return fmt.Errorf("%s is not set in ConfigMap %q", configNameClusterName, defaults.ConfigMapName)
	}

	clusterName := cm.Data[configNameClusterName]

	k.Log("🔑 Patching existing secret %s...", defaults.ClusterMeshSecretName)
	meshSecret, err := src.GetSecret(ctx, k.params.Namespace, defaults.ClusterMeshSecretName, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("clustermesh configuration secret %s does not exist", defaults.ClusterMeshSecretName)
	}

	for _, suffix := range []string{"", caSuffix, keySuffix, certSuffix} {
		if _, ok := meshSecret.Data[clusterName+suffix]; !ok {
			k.Log("⚠️  Key %q does not exist in secret. Cluster already disconnected?", clusterName+suffix)
			continue
		}

		patch := []byte(`[{"op": "remove", "path": "/data/` + clusterName + suffix + `"}]`)
		_, err = src.PatchSecret(ctx, k.params.Namespace, defaults.ClusterMeshSecretName, types.JSONPatchType, patch, metav1.PatchOptions{})
		if err != nil {
			k.Log("❌ Warning: Unable to patch secret %s with path %q: %s", defaults.ClusterMeshSecretName, patch, err)
		}
	}

	return nil
}

func (k *K8sClusterMesh) Disconnect(ctx context.Context) error {
	remoteCluster, err := k8s.NewClient(k.params.DestinationContext, "")
	if err != nil {
		return fmt.Errorf("unable to create Kubernetes client to access remote cluster %q: %w", k.params.DestinationContext, err)
	}

	if err := k.disconnectCluster(ctx, k.client, remoteCluster); err != nil {
		return err
	}

	if err := k.disconnectCluster(ctx, remoteCluster, k.client); err != nil {
		return err
	}

	return nil
}

type Status struct {
	AccessInformation *accessInformation
	Service           *corev1.Service
	Connectivity      *ConnectivityStatus
}

func (k *K8sClusterMesh) statusAccessInformation(ctx context.Context, log bool) (*accessInformation, error) {
	w := utils.NewWaitObserver(ctx, utils.WaitParameters{Log: func(err error, wait string) {
		if log {
			k.Log("⌛ Waiting (%s) for access information: %s", wait, err)
		}
	}})
	defer w.Cancel()

retry:
	ai, err := k.extractAccessInformation(ctx, k.client, []string{}, false)
	if err != nil && k.params.Wait {
		if err := w.Retry(err); err != nil {
			return nil, err
		}
		goto retry
	}

	return ai, err
}

func (k *K8sClusterMesh) statusService(ctx context.Context, log bool) (*corev1.Service, error) {
	w := utils.NewWaitObserver(ctx, utils.WaitParameters{Log: func(err error, wait string) {
		if log {
			k.Log("⌛ Waiting (%s) for ClusterMesh service to be available: %s", wait, err)
		}
	}})
	defer w.Cancel()

retry:
	svc, err := k.client.GetService(ctx, k.params.Namespace, defaults.ClusterMeshServiceName, metav1.GetOptions{})
	if err != nil {
		if k.params.Wait {
			if err := w.Retry(err); err != nil {
				return nil, err
			}
			goto retry
		}

		return nil, fmt.Errorf("clustermesh-apiserver cannot be found: %w", err)
	}

	return svc, nil
}

type StatisticalStatus struct {
	Min int64
	Avg float64
	Max int64
}

type ClusterStats struct {
	Configured int
	Connected  int
}

type ConnectivityStatus struct {
	GlobalServices StatisticalStatus
	Connected      StatisticalStatus
	Clusters       map[string]*ClusterStats
	Total          int64
	NotReady       int64
	Errors         status.ErrorCountMapMap
}

func (c *ConnectivityStatus) addError(pod, cluster string, err error) {
	m := c.Errors[pod]
	if m == nil {
		m = status.ErrorCountMap{}
		c.Errors[pod] = m
	}

	if m[cluster] == nil {
		m[cluster] = &status.ErrorCount{}
	}

	m[cluster].Errors = append(m[cluster].Errors, err)
}

func (c *ConnectivityStatus) parseAgentStatus(name string, s *status.ClusterMeshAgentConnectivityStatus) {
	if c.GlobalServices.Min < 0 || c.GlobalServices.Min > s.GlobalServices {
		c.GlobalServices.Min = s.GlobalServices
	}

	if c.GlobalServices.Max < s.GlobalServices {
		c.GlobalServices.Max = s.GlobalServices
	}

	c.GlobalServices.Avg += float64(s.GlobalServices)
	c.Total++

	ready := int64(0)
	for _, cluster := range s.Clusters {
		stats, ok := c.Clusters[cluster.Name]
		if !ok {
			stats = &ClusterStats{}
			c.Clusters[cluster.Name] = stats
		}

		stats.Configured++

		if cluster.Ready {
			ready++
			stats.Connected++
		} else {
			c.addError(name, cluster.Name, fmt.Errorf("cluster is not ready: %s", cluster.Status))
		}
	}

	if ready != int64(len(s.Clusters)) {
		c.NotReady++
	}

	if c.Connected.Min < 0 || c.Connected.Min > ready {
		c.Connected.Min = ready
	}

	if c.Connected.Max < ready {
		c.Connected.Max = ready
	}

	c.Connected.Avg += float64(ready)
}

func (k *K8sClusterMesh) statusConnectivity(ctx context.Context, log bool) (*ConnectivityStatus, error) {
	w := utils.NewWaitObserver(ctx, utils.WaitParameters{Log: func(err error, wait string) {
		if log {
			k.Log("⌛ Waiting (%s) for clusters to be connected: %s", wait, err)
		}
	}})
	defer w.Cancel()

retry:
	status, err := k.determineStatusConnectivity(ctx)
	if k.params.Wait {
		if err == nil {
			if status.NotReady > 0 {
				err = fmt.Errorf("%d clusters not ready", status.NotReady)
			}
			if len(status.Errors) > 0 {
				err = fmt.Errorf("%d clusters have errors", len(status.Errors))
			}
		}

		if err != nil {
			if err := w.Retry(err); err != nil {
				return nil, err
			}
			goto retry
		}
	}

	return status, err
}

func (k *K8sClusterMesh) determineStatusConnectivity(ctx context.Context) (*ConnectivityStatus, error) {
	stats := &ConnectivityStatus{
		GlobalServices: StatisticalStatus{Min: -1},
		Connected:      StatisticalStatus{Min: -1},
		Errors:         status.ErrorCountMapMap{},
		Clusters:       map[string]*ClusterStats{},
	}

	pods, err := k.client.ListPods(ctx, k.params.Namespace, metav1.ListOptions{LabelSelector: "k8s-app=cilium"})
	if err != nil {
		return nil, fmt.Errorf("unable to list cilium pods: %w", err)
	}

	for _, pod := range pods.Items {
		s, err := k.statusCollector.ClusterMeshConnectivity(ctx, pod.Name)
		if err != nil {
			if err == status.ErrClusterMeshStatusNotAvailable {
				continue
			}
			return nil, fmt.Errorf("unable to determine status of cilium pod %q: %w", pod.Name, err)
		}

		stats.parseAgentStatus(pod.Name, s)
	}

	if len(pods.Items) > 0 {
		stats.GlobalServices.Avg /= float64(len(pods.Items))
		stats.Connected.Avg /= float64(len(pods.Items))
	}

	return stats, nil
}

func (k *K8sClusterMesh) Status(ctx context.Context, log bool) (*Status, error) {
	var (
		err error
		s   = &Status{}
	)

	collector, err := status.NewK8sStatusCollector(ctx, k.client, status.K8sStatusParameters{
		Namespace: k.params.Namespace,
	})
	if err != nil {
		return nil, fmt.Errorf("unable to create client to collect status: %w", err)
	}

	k.statusCollector = collector

	ctx, cancel := context.WithTimeout(ctx, k.params.waitTimeout())
	defer cancel()

	s.AccessInformation, err = k.statusAccessInformation(ctx, log)
	if err != nil {
		return nil, err
	}

	if log {
		k.Log("✅ Cluster access information is available:")
		for _, ip := range s.AccessInformation.ServiceIPs {
			k.Log("  - %s:%d", ip, s.AccessInformation.ServicePort)
		}
	}

	s.Service, err = k.statusService(ctx, log)
	if err != nil {
		return nil, err
	}

	if log {
		k.Log("✅ Service %q of type %q found", defaults.ClusterMeshServiceName, s.Service.Spec.Type)
	}

	if s.Service.Spec.Type == corev1.ServiceTypeLoadBalancer {
		if len(s.AccessInformation.ServiceIPs) == 0 {
			if log {
				k.Log("❌ Service is of type LoadBalancer but has no IPs assigned")
			}
			return nil, fmt.Errorf("no IP available to reach cluster")
		}
	}

	s.Connectivity, err = k.statusConnectivity(ctx, log)

	if log && s.Connectivity != nil {
		if len(s.Connectivity.Clusters) == 0 {
			k.Log("⚠️  Cluster not configured for clustermesh, use '--cluster-id' and '--cluster-name' with 'cilium install'. External workloads may still be configured.")
			return s, nil
		} else if s.Connectivity.NotReady > 0 {
			k.Log("⚠️  %d/%d nodes are not connected to all clusters [min:%d / avg:%.1f / max:%d]",
				s.Connectivity.NotReady,
				s.Connectivity.Total,
				s.Connectivity.Connected.Min,
				s.Connectivity.Connected.Avg,
				s.Connectivity.Connected.Max)
		} else {
			k.Log("✅ All %d nodes are connected to all clusters [min:%d / avg:%.1f / max:%d]",
				s.Connectivity.Total,
				s.Connectivity.Connected.Min,
				s.Connectivity.Connected.Avg,
				s.Connectivity.Connected.Max)
		}

		k.Log("🔌 Cluster Connections:")
		for cluster, stats := range s.Connectivity.Clusters {
			k.Log("- %s: %d/%d configured, %d/%d connected",
				cluster, stats.Configured, s.Connectivity.Total,
				stats.Connected, s.Connectivity.Total)
		}

		k.Log("🔀 Global services: [ min:%d / avg:%.1f / max:%d ]",
			s.Connectivity.GlobalServices.Min,
			s.Connectivity.GlobalServices.Avg,
			s.Connectivity.GlobalServices.Max)

		if len(s.Connectivity.Errors) > 0 {
			k.Log("❌ %d Errors:", len(s.Connectivity.Errors))

			for podName, clusters := range s.Connectivity.Errors {
				for clusterName, a := range clusters {
					for _, err := range a.Errors {
						k.Log("❌ %s is not connected to cluster %s: %s", podName, clusterName, err)
					}
				}
			}
		}
	}

	if err != nil {
		return nil, err
	}

	return s, nil
}

func (k *K8sClusterMesh) CreateExternalWorkload(ctx context.Context, names []string) error {
	count := 0
	for _, name := range names {
		cew := &ciliumv2.CiliumExternalWorkload{
			ObjectMeta: metav1.ObjectMeta{
				Name:        name,
				Labels:      k.params.Labels,
				Annotations: map[string]string{},
			},
			Spec: ciliumv2.CiliumExternalWorkloadSpec{
				IPv4AllocCIDR: k.params.IPv4AllocCIDR,
				IPv6AllocCIDR: k.params.IPv6AllocCIDR,
			},
		}

		_, err := k.client.CreateCiliumExternalWorkload(ctx, cew, metav1.CreateOptions{})
		if err != nil {
			return err
		}
		count++
	}
	k.Log("✅ Added %d external workload resources.", count)
	return nil
}

func (k *K8sClusterMesh) DeleteExternalWorkload(ctx context.Context, names []string) error {
	var errs []string
	count := 0

	if len(names) == 0 && k.params.All {
		cewList, err := k.client.ListCiliumExternalWorkloads(ctx, metav1.ListOptions{})
		if err != nil {
			return err
		}
		for _, cew := range cewList.Items {
			names = append(names, cew.Name)
		}
	}
	for _, name := range names {
		err := k.client.DeleteCiliumExternalWorkload(ctx, name, metav1.DeleteOptions{})
		if err != nil {
			errs = append(errs, err.Error())
		} else {
			count++
		}
	}
	if count > 0 {
		k.Log("✅ Removed %d external workload resources.", count)
	}
	if len(errs) > 0 {
		return errors.New(strings.Join(errs, ", "))
	}
	return nil
}

var installScriptFmt = `#!/bin/bash
CILIUM_IMAGE=${1:-%[1]s}
CLUSTER_ADDR=${2:-%[2]s}

set -e
shopt -s extglob

if [ "$1" = "uninstall" ] ; then
    if [ -n "$(sudo docker ps -a -q -f name=cilium)" ]; then
        echo "Shutting down running Cilium agent"
        sudo docker rm -f cilium || true
    fi
    if [ -f /usr/bin/cilium ] ; then
        echo "Removing /usr/bin/cilium"
        sudo rm /usr/bin/cilium
    fi
    pushd /etc
    if [ -f resolv.conf.orig ] ; then
        echo "Restoring /etc/resolv.conf"
        sudo mv -f resolv.conf.orig resolv.conf
    elif [ -f resolv.conf.link ] && [ -f $(cat resolv.conf.link) ] ; then
        echo "Restoring systemd resolved config..."
        if [ -f /usr/lib/systemd/resolved.conf.d/cilium-kube-dns.conf ] ; then
	    sudo rm /usr/lib/systemd/resolved.conf.d/cilium-kube-dns.conf
        fi
        sudo systemctl daemon-reload
        sudo systemctl reenable systemd-resolved.service
        sudo service systemd-resolved restart
        sudo ln -fs $(cat resolv.conf.link) resolv.conf
        sudo rm resolv.conf.link
    fi
    popd
    exit 0
fi

if [ -z "$CLUSTER_ADDR" ] ; then
    echo "CLUSTER_ADDR must be defined to the IP:PORT at which the clustermesh-apiserver is reachable."
    exit 1
fi

port='@(6553[0-5]|655[0-2][0-9]|65[0-4][0-9][0-9]|6[0-4][0-9][0-9][0-9]|[1-5][0-9][0-9][0-9][0-9]|[1-9][0-9][0-9][0-9]|[1-9][0-9][0-9]|[1-9][0-9]|[1-9])'
byte='@(25[0-5]|2[0-4][0-9]|[1][0-9][0-9]|[1-9][0-9]|[0-9])'
ipv4="$byte\.$byte\.$byte\.$byte"

# Default port is for a HostPort service
case "$CLUSTER_ADDR" in
    \[+([0-9a-fA-F:])\]:$port)
	CLUSTER_PORT=${CLUSTER_ADDR##\[*\]:}
	CLUSTER_IP=${CLUSTER_ADDR#\[}
	CLUSTER_IP=${CLUSTER_IP%%\]:*}
	;;
    [^[]$ipv4:$port)
	CLUSTER_PORT=${CLUSTER_ADDR##*:}
	CLUSTER_IP=${CLUSTER_ADDR%%:*}
	;;
    *:*)
	echo "Malformed CLUSTER_ADDR: $CLUSTER_ADDR"
	exit 1
	;;
    *)
	CLUSTER_PORT=2379
	CLUSTER_IP=$CLUSTER_ADDR
	;;
esac

sudo mkdir -p /var/lib/cilium/etcd
sudo tee /var/lib/cilium/etcd/ca.crt <<EOF >/dev/null
%[3]sEOF
sudo tee /var/lib/cilium/etcd/tls.crt <<EOF >/dev/null
%[4]sEOF
sudo tee /var/lib/cilium/etcd/tls.key <<EOF >/dev/null
%[5]sEOF
sudo tee /var/lib/cilium/etcd/config.yaml <<EOF >/dev/null
---
trusted-ca-file: /var/lib/cilium/etcd/ca.crt
cert-file: /var/lib/cilium/etcd/tls.crt
key-file: /var/lib/cilium/etcd/tls.key
endpoints:
- https://clustermesh-apiserver.cilium.io:$CLUSTER_PORT
EOF

CILIUM_OPTS=" --join-cluster --enable-host-reachable-services --enable-endpoint-health-checking=false"
CILIUM_OPTS+=" --kvstore etcd --kvstore-opt etcd.config=/var/lib/cilium/etcd/config.yaml"
if [ -n "$HOST_IP" ] ; then
    CILIUM_OPTS+=" --ipv4-node $HOST_IP"
fi
if [ -n "$DEBUG" ] ; then
    CILIUM_OPTS+=" --debug --restore=false"
fi

DOCKER_OPTS=" -d --log-driver syslog --restart always"
DOCKER_OPTS+=" --privileged --network host --cap-add NET_ADMIN --cap-add SYS_MODULE"
DOCKER_OPTS+=" --volume /var/lib/cilium/etcd:/var/lib/cilium/etcd"
DOCKER_OPTS+=" --volume /var/run/cilium:/var/run/cilium"
DOCKER_OPTS+=" --volume /boot:/boot"
DOCKER_OPTS+=" --volume /lib/modules:/lib/modules"
DOCKER_OPTS+=" --volume /sys/fs/bpf:/sys/fs/bpf"
DOCKER_OPTS+=" --volume /run/xtables.lock:/run/xtables.lock"
DOCKER_OPTS+=" --add-host clustermesh-apiserver.cilium.io:$CLUSTER_IP"

if [ -n "$(sudo docker ps -a -q -f name=cilium)" ]; then
    echo "Shutting down running Cilium agent"
    sudo docker rm -f cilium || true
fi

echo "Launching Cilium agent $CILIUM_IMAGE..."
sudo docker run --name cilium $DOCKER_OPTS $CILIUM_IMAGE cilium-agent $CILIUM_OPTS

# Copy Cilium CLI
sudo docker cp cilium:/usr/bin/cilium /usr/bin/cilium

# Wait for cilium agent to become available
cilium_started=false
for ((i = 0 ; i < 24; i++)); do
    if cilium status --brief > /dev/null 2>&1; then
        cilium_started=true
        break
    fi
    sleep 5s
    echo "Waiting for Cilium daemon to come up..."
done

if [ "$cilium_started" = true ] ; then
    echo 'Cilium successfully started!'
else
    >&2 echo 'Timeout waiting for Cilium to start.'
    exit 1
fi

# Wait for kube-dns service to become available
kubedns=""
for ((i = 0 ; i < 24; i++)); do
    kubedns=$(cilium service list get -o jsonpath='{[?(@.spec.frontend-address.port==53)].spec.frontend-address.ip}')
    if [ -n "$kubedns" ] ; then
        break
    fi
    sleep 5s
    echo "Waiting for kube-dns service to come available..."
done

if [ -n "$kubedns" ] ; then
    if grep "nameserver $kubedns" /etc/resolv.conf ; then
	echo "kube-dns IP $kubedns already in /etc/resolv.conf"
    else
	linkval=$(readlink /etc/resolv.conf) && echo "$linkval" | sudo tee /etc/resolv.conf.link || true
	if [[ "$linkval" == *"/systemd/"* ]] ; then
	    echo "updating systemd resolved with kube-dns IP $kubedns"
	    sudo mkdir -p /usr/lib/systemd/resolved.conf.d
	    sudo tee /usr/lib/systemd/resolved.conf.d/cilium-kube-dns.conf <<EOF >/dev/null
# This file is installed by Cilium to use kube dns server from a non-k8s node.
[Resolve]
DNS=$kubedns
EOF
	    sudo systemctl daemon-reload
	    sudo systemctl reenable systemd-resolved.service
	    sudo service systemd-resolved restart
	    sudo ln -fs /run/systemd/resolve/resolv.conf /etc/resolv.conf
	else
	    echo "Adding kube-dns IP $kubedns to /etc/resolv.conf"
	    sudo cp /etc/resolv.conf /etc/resolv.conf.orig
	    resolvconf="nameserver $kubedns\n$(cat /etc/resolv.conf)\n"
	    printf "$resolvconf" | sudo tee /etc/resolv.conf
	fi
    fi
else
    >&2 echo "kube-dns not found."
    exit 1
fi
`

func (k *K8sClusterMesh) WriteExternalWorkloadInstallScript(ctx context.Context, writer io.Writer) error {
	daemonSet, err := k.client.GetDaemonSet(ctx, k.params.Namespace, defaults.AgentDaemonSetName, metav1.GetOptions{})
	if err != nil {
		return err
	}
	if daemonSet == nil {
		return fmt.Errorf("DaemomSet %s is not available", defaults.AgentDaemonSetName)
	}
	k.Log("✅ Using image from Cilium DaemonSet: %s", daemonSet.Spec.Template.Spec.Containers[0].Image)

	ai, err := k.statusAccessInformation(ctx, false)
	if err != nil {
		return err
	}
	clusterAddr := fmt.Sprintf("%s:%d", ai.ServiceIPs[0], ai.ServicePort)
	k.Log("✅ Using clustermesh-apiserver service address: %s", clusterAddr)

	fmt.Fprintf(writer, installScriptFmt,
		daemonSet.Spec.Template.Spec.Containers[0].Image, clusterAddr,
		string(ai.CA), string(ai.ExternalWorkloadCert), string(ai.ExternalWorkloadKey))
	return nil
}

func formatCEW(cew ciliumv2.CiliumExternalWorkload) string {
	var items []string
	ip := cew.Status.IP
	if ip == "" {
		ip = "N/A"
	}
	items = append(items, fmt.Sprintf("IP: %s", ip))
	var labels []string
	for key, value := range cew.Labels {
		labels = append(labels, fmt.Sprintf("%s=%s", key, value))
	}
	items = append(items, fmt.Sprintf("Labels: %s", strings.Join(labels, ",")))
	return strings.Join(items, ", ")
}

func (k *K8sClusterMesh) ExternalWorkloadStatus(ctx context.Context, names []string) error {
	log := true

	collector, err := status.NewK8sStatusCollector(ctx, k.client, status.K8sStatusParameters{
		Namespace: k.params.Namespace,
	})
	if err != nil {
		return fmt.Errorf("unable to create client to collect status: %w", err)
	}

	k.statusCollector = collector

	ctx, cancel := context.WithTimeout(ctx, k.params.waitTimeout())
	defer cancel()

	ai, err := k.statusAccessInformation(ctx, log)
	if err != nil {
		return err
	}

	if log {
		k.Log("✅ Cluster access information is available:")
		for _, ip := range ai.ServiceIPs {
			k.Log("	 - %s:%d", ip, ai.ServicePort)
		}
	}

	svc, err := k.statusService(ctx, log)
	if err != nil {
		return err
	}

	if log {
		k.Log("✅ Service %q of type %q found", defaults.ClusterMeshServiceName, svc.Spec.Type)
	}

	if svc.Spec.Type == corev1.ServiceTypeLoadBalancer {
		if len(ai.ServiceIPs) == 0 {
			if log {
				k.Log("❌ Service is of type LoadBalancer but has no IPs assigned")
			}
			return fmt.Errorf("no IP available to reach cluster")
		}
	}
	var cews []ciliumv2.CiliumExternalWorkload

	if len(names) == 0 {
		cewList, err := k.client.ListCiliumExternalWorkloads(ctx, metav1.ListOptions{})
		if err != nil {
			return err
		}
		cews = cewList.Items
		if log {
			if len(cews) == 0 {
				k.Log("⚠️  No external workloads found.")
				return nil
			}
		}
	} else {
		for _, name := range names {
			cew, err := k.client.GetCiliumExternalWorkload(ctx, name, metav1.GetOptions{})
			if err != nil {
				return err
			}
			cews = append(cews, *cew)
		}
	}

	var buf bytes.Buffer
	w := tabwriter.NewWriter(&buf, 0, 0, 4, ' ', 0)

	header := "External Workloads"
	for _, cew := range cews {
		fmt.Fprintf(w, "%s\t%s\t%s\n", header, cew.Name, formatCEW(cew))
		header = ""
	}

	w.Flush()
	fmt.Println(buf.String())
	return err
}
