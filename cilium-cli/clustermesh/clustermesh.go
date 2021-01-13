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
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/cilium/cilium-cli/defaults"
	"github.com/cilium/cilium-cli/internal/certs"
	"github.com/cilium/cilium-cli/internal/k8s"
	"github.com/cilium/cilium-cli/status"

	"github.com/cilium/cilium/api/v1/models"
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

	retryInterval = 2 * time.Second
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

func (k *K8sClusterMesh) generateService() *corev1.Service {
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
		svc.Spec.Type = corev1.ServiceType(k.params.ServiceType)
	} else {
		switch k.flavor.Kind {
		case k8s.KindGKE:
			k.Log("🔮 Auto-exposing service within GCP VPC (cloud.google.com/load-balancer-type=internal)")
			svc.Spec.Type = corev1.ServiceTypeLoadBalancer
			svc.ObjectMeta.Annotations["cloud.google.com/load-balancer-type"] = "Internal"
			// if all the clusters are in the same region the next annotation can be removed
			svc.ObjectMeta.Annotations["networking.gke.io/internal-load-balancer-allow-global-access"] = "true"
		case k8s.KindEKS:
			k.Log("🔮 Auto-exposing service within AWS VPC (service.beta.kubernetes.io/aws-load-balancer-internal: 0.0.0.0/0")
			svc.Spec.Type = corev1.ServiceTypeLoadBalancer
			svc.ObjectMeta.Annotations["service.beta.kubernetes.io/aws-load-balancer-internal"] = "0.0.0.0/0"
		default:
			svc.Spec.Type = corev1.ServiceTypeClusterIP
		}
	}

	return svc
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
	Writer               io.Writer
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

func (k *K8sClusterMesh) Validate(ctx context.Context) error {
	f, err := k.client.AutodetectFlavor(ctx)
	if err != nil {
		return err
	}
	k.flavor = f

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
	k.clusterID = clusterID

	clusterName, ok := cm.Data[configNameClusterName]
	if !ok {
		k.Log("❌ Cluster name (%q) is not set", configNameClusterName)
		failures++
	}

	if clusterName == "" || clusterName == "default" {
		k.Log("❌ Cluster name (%q) must be set to a value other than \"default\"", configNameClusterName)
		failures++
	}
	k.clusterName = clusterName

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

	if _, err := k.client.CreateDeployment(ctx, k.params.Namespace, k.generateDeployment(), metav1.CreateOptions{}); err != nil {
		return err
	}

	if _, err := k.client.CreateService(ctx, k.params.Namespace, k.generateService(), metav1.CreateOptions{}); err != nil {
		return err
	}

	return nil
}

type accessInformation struct {
	ServiceIPs  []string
	ServicePort int
	ClusterName string
	CA          []byte
	ClientCert  []byte
	ClientKey   []byte
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

	clusterName := cm.Data[configNameClusterName]

	if verbose {
		k.Log("✨ Extracting access information of cluster %s...", clusterName)
	}
	svc, err := client.GetService(ctx, k.params.Namespace, defaults.ClusterMeshServiceName, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("unable to get clustermesh service %q: %w", defaults.ClusterMeshServiceName, err)
	}

	if verbose {
		k.Log("🔑 Extracing secrets from cluster %s...", clusterName)
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

	ai := &accessInformation{
		ClusterName: cm.Data[configNameClusterName],
		CA:          caCert,
		ClientKey:   clientKey,
		ClientCert:  clientCert,
		ServiceIPs:  []string{},
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
		return nil, fmt.Errorf("not able to derive service IPs for type ClusterIP, please specify IPs manually")

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

	aiLocal, err := k.extractAccessInformation(ctx, k.client, k.params.SourceEndpoints, true)
	if err != nil {
		k.Log("❌ Unable to retrieve access information of local cluster %q: %s", k.client.ClusterName(), err)
		return err
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

func (k *K8sClusterMesh) statusAccessInformation(ctx context.Context) (*accessInformation, error) {
retry:
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	ai, err := k.extractAccessInformation(ctx, k.client, []string{}, false)
	if err != nil && k.params.Wait {
		time.Sleep(retryInterval)
		goto retry
	}

	return ai, err
}

func (k *K8sClusterMesh) statusService(ctx context.Context) (*corev1.Service, error) {
retry:
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	svc, err := k.client.GetService(ctx, k.params.Namespace, defaults.ClusterMeshServiceName, metav1.GetOptions{})
	if err != nil {
		if k.params.Wait {
			time.Sleep(retryInterval)
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

func (k *K8sClusterMesh) statusConnectivity(ctx context.Context) (*ConnectivityStatus, error) {
	status := &ConnectivityStatus{
		GlobalServices: StatisticalStatus{Min: -1},
		Connected:      StatisticalStatus{Min: -1},
		Errors:         status.ErrorCountMapMap{},
		Clusters:       map[string]*ClusterStats{},
	}
retry:
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	pods, err := k.client.ListPods(ctx, k.params.Namespace, metav1.ListOptions{LabelSelector: "k8s-app=cilium"})
	if err != nil {
		if k.params.Wait {
			time.Sleep(retryInterval)
			goto retry
		}

		return nil, fmt.Errorf("unable to list cilium pods: %w", err)
	}

	for _, pod := range pods.Items {
		s, err := k.statusCollector.ClusterMeshConnectivity(ctx, pod.Name)
		if err != nil {
			return nil, fmt.Errorf("unable to determine status of cilium pod %q: %w", pod.Name, err)
		}

		status.parseAgentStatus(pod.Name, s)
	}

	status.GlobalServices.Avg /= float64(len(pods.Items))
	status.Connected.Avg /= float64(len(pods.Items))

	return status, nil
}

func (k *K8sClusterMesh) Status(ctx context.Context, log bool) (*Status, error) {
	var (
		err error
		s   = &Status{}
	)

	collector, err := status.NewK8sStatusCollector(ctx, k.client, status.K8sStatusParameters{
		Namespace:    k.params.Namespace,
		Wait:         k.params.Wait,
		WaitDuration: k.params.WaitDuration,
	})
	if err != nil {
		return nil, fmt.Errorf("unable to create client to collect status: %w", err)
	}

	k.statusCollector = collector

	ctx, cancel := context.WithTimeout(ctx, k.params.waitTimeout())
	defer cancel()

	s.AccessInformation, err = k.statusAccessInformation(ctx)
	if err != nil {
		return nil, err
	}

	if log {
		k.Log("✅ Cluster access information is available:")
		for _, ip := range s.AccessInformation.ServiceIPs {
			k.Log("  - %s:%d", ip, s.AccessInformation.ServicePort)
		}
	}

	s.Service, err = k.statusService(ctx)
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
			return nil, fmt.Errorf("No IP available to reach cluster")
		}
	}

	s.Connectivity, err = k.statusConnectivity(ctx)
	if err != nil {
		return nil, err
	}

	if log {
		if s.Connectivity.NotReady > 0 {
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

	return s, nil
}
