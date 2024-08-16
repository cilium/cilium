// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package clustermesh

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"golang.org/x/exp/maps"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"

	"github.com/blang/semver/v4"
	"github.com/cilium/cilium/api/v1/models"
	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"helm.sh/helm/v3/pkg/release"

	"github.com/cilium/cilium-cli/defaults"
	"github.com/cilium/cilium-cli/internal/certs"
	"github.com/cilium/cilium-cli/internal/helm"
	"github.com/cilium/cilium-cli/internal/utils"
	"github.com/cilium/cilium-cli/k8s"
	"github.com/cilium/cilium-cli/status"
	"github.com/cilium/cilium-cli/utils/wait"
)

const (
	configNameClusterID   = "cluster-id"
	configNameClusterName = "cluster-name"

	configNameTunnelLegacy         = "tunnel"
	configNameTunnelProtocol       = "tunnel-protocol"
	configNameRoutingMode          = "routing-mode"
	configNameMaxConnectedClusters = "max-connected-clusters"

	configNameIdentityAllocationMode = "identity-allocation-mode"

	caSuffix   = ".etcd-client-ca.crt"
	keySuffix  = ".etcd-client.key"
	certSuffix = ".etcd-client.crt"
)

var (
	replicas                 = int32(1)
	deploymentMaxSurge       = intstr.FromInt(1)
	deploymentMaxUnavailable = intstr.FromInt(1)
	secretDefaultMode        = int32(0400)
	// This can be replaced with cilium/pkg/defaults.MaxConnectedClusters once
	// changes are merged there.
	maxConnectedClusters = defaults.ClustermeshMaxConnectedClusters
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
		if corev1.ServiceType(k.params.ServiceType) == corev1.ServiceTypeNodePort {
			k.Log("⚠️  Using service type NodePort may fail when nodes are removed from the cluster!")
		}
		svc.Spec.Type = corev1.ServiceType(k.params.ServiceType)

		svc.ObjectMeta.Annotations = k.params.ServiceAnnotations
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
export rootpw="$(head /dev/urandom | tr -dc A-Za-z0-9 | head -c 16)";
echo $rootpw | etcdctl --interactive=false user add root;
etcdctl user grant-role root root;
export vmpw="$(head /dev/urandom | tr -dc A-Za-z0-9 | head -c 16)";
echo $vmpw | etcdctl --interactive=false user add externalworkload;
etcdctl role add externalworkload;
etcdctl role grant-permission externalworkload --from-key read '';
etcdctl role grant-permission externalworkload readwrite --prefix cilium/state/noderegister/v1/;
etcdctl role grant-permission externalworkload readwrite --prefix cilium/.initlock/;
etcdctl user grant-role externalworkload externalworkload;
export remotepw="$(head /dev/urandom | tr -dc A-Za-z0-9 | head -c 16)";
echo $remotepw | etcdctl --interactive=false user add remote;
etcdctl role add remote;
etcdctl role grant-permission remote --from-key read '';
etcdctl user grant-role remote remote;
etcdctl auth enable;
exit`}

func (k *K8sClusterMesh) apiserverImage() string {
	return utils.BuildImagePath(k.params.ApiserverImage, k.params.ApiserverVersion, defaults.ClusterMeshApiserverImage, k.imageVersion)
}

func (k *K8sClusterMesh) etcdImage() string {
	etcdVersion := "v3.5.4"
	if k.clusterArch == "amd64" {
		return "quay.io/coreos/etcd:" + etcdVersion
	}
	return "quay.io/coreos/etcd:" + etcdVersion + "-" + k.clusterArch
}

func (k *K8sClusterMesh) etcdEnvs() []corev1.EnvVar {
	envs := []corev1.EnvVar{
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
	}
	if k.clusterArch == "arm64" {
		envs = append(envs, corev1.EnvVar{
			Name:  "ETCD_UNSUPPORTED_ARCH",
			Value: "arm64",
		})
	}
	return envs
}

func (k *K8sClusterMesh) generateDeployment(clustermeshApiserverArgs []string) *appsv1.Deployment {

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
								// Surrounding the IPv4 address with brackets works in this case, since etcd
								// uses net.SplitHostPort() internally and it accepts that format.
								"--listen-client-urls=https://127.0.0.1:2379,https://[$(HOSTNAME_IP)]:2379",
								"--advertise-client-urls=https://[$(HOSTNAME_IP)]:2379",
								"--initial-cluster-token=clustermesh-apiserver",
								"--auto-compaction-retention=1",
							},
							Image:           k.etcdImage(),
							ImagePullPolicy: corev1.PullIfNotPresent,
							Env:             k.etcdEnvs(),
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
							Args: append(clustermeshApiserverArgs,
								"--cluster-name="+k.clusterName,
								"--cluster-id="+k.clusterID,
								"--kvstore-opt",
								"etcd.config=/var/lib/cilium/etcd-config.yaml",
							),
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
							Image:           k.etcdImage(),
							ImagePullPolicy: corev1.PullIfNotPresent,
							Env:             k.etcdEnvs(),
							VolumeMounts: []corev1.VolumeMount{
								{
									Name:      "etcd-data-dir",
									MountPath: "/var/run/etcd",
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
	CheckDeploymentStatus(ctx context.Context, namespace, deployment string) error
	CreateService(ctx context.Context, namespace string, service *corev1.Service, opts metav1.CreateOptions) (*corev1.Service, error)
	DeleteService(ctx context.Context, namespace, name string, opts metav1.DeleteOptions) error
	GetService(ctx context.Context, namespace, name string, opts metav1.GetOptions) (*corev1.Service, error)
	PatchDaemonSet(ctx context.Context, namespace, name string, pt types.PatchType, data []byte, opts metav1.PatchOptions) (*appsv1.DaemonSet, error)
	GetDaemonSet(ctx context.Context, namespace, name string, options metav1.GetOptions) (*appsv1.DaemonSet, error)
	ListNodes(ctx context.Context, options metav1.ListOptions) (*corev1.NodeList, error)
	ListPods(ctx context.Context, namespace string, options metav1.ListOptions) (*corev1.PodList, error)
	AutodetectFlavor(ctx context.Context) k8s.Flavor
	CiliumStatus(ctx context.Context, namespace, pod string) (*models.StatusResponse, error)
	ClusterName() string
	ListCiliumExternalWorkloads(ctx context.Context, opts metav1.ListOptions) (*ciliumv2.CiliumExternalWorkloadList, error)
	GetCiliumExternalWorkload(ctx context.Context, name string, opts metav1.GetOptions) (*ciliumv2.CiliumExternalWorkload, error)
	CreateCiliumExternalWorkload(ctx context.Context, cew *ciliumv2.CiliumExternalWorkload, opts metav1.CreateOptions) (*ciliumv2.CiliumExternalWorkload, error)
	DeleteCiliumExternalWorkload(ctx context.Context, name string, opts metav1.DeleteOptions) error
	GetRunningCiliumVersion(ctx context.Context, namespace string) (string, error)
	ListCiliumEndpoints(ctx context.Context, namespace string, options metav1.ListOptions) (*ciliumv2.CiliumEndpointList, error)
	GetPlatform(ctx context.Context) (*k8s.Platform, error)
	CiliumLogs(ctx context.Context, namespace, pod string, since time.Time, filter *regexp.Regexp) (string, error)
	GetHelmState(ctx context.Context, namespace string, secretName string) (*helm.State, error)
}

type K8sClusterMesh struct {
	client          k8sClusterMeshImplementation
	certManager     *certs.CertManager
	statusCollector *status.K8sStatusCollector
	flavor          k8s.Flavor
	params          Parameters
	clusterName     string
	clusterID       string
	imageVersion    string
	clusterArch     string
	externalKVStore bool
}

type Parameters struct {
	Namespace            string
	ServiceType          string
	ServiceAnnotations   map[string]string
	DestinationContext   string
	Wait                 bool
	WaitDuration         time.Duration
	DestinationEndpoints []string
	SourceEndpoints      []string
	ApiserverImage       string
	ApiserverVersion     string
	CreateCA             bool
	Writer               io.Writer
	Labels               map[string]string
	IPv4AllocCIDR        string
	IPv6AllocCIDR        string
	All                  bool
	ConfigOverwrites     []string
	Retries              int
	Output               string

	// EnableExternalWorkloads indicates whether externalWorkloads.enabled Helm value
	// should be set to true. For Helm mode only.
	EnableExternalWorkloads bool

	// EnableKVStoreMesh indicates whether kvstoremesh should be enabled.
	// For Helm mode only.
	EnableKVStoreMesh bool
}

func (p Parameters) validateParams() error {
	if p.ApiserverImage != defaults.ClusterMeshApiserverImage {
		return nil
	} else if err := utils.CheckVersion(p.ApiserverVersion); err != nil {
		return err
	}
	return nil
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
	k.flavor = k.client.AutodetectFlavor(ctx)

	cm, err := k.client.GetConfigMap(ctx, k.params.Namespace, defaults.ConfigMapName, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("unable to retrieve ConfigMap %q: %w", defaults.ConfigMapName, err)
	}

	k.externalKVStore = cm.Data[configNameIdentityAllocationMode] != "crd"

	clusterID := cm.Data[configNameClusterID]
	if clusterID == "" {
		clusterID = "0"
	}
	k.clusterID = clusterID

	clusterName := cm.Data[configNameClusterName]
	if clusterName == "" {
		clusterName = "default"
	}
	k.clusterName = clusterName

	if clusterID == "0" || clusterName == "default" {
		k.Log("⚠️  Cluster not configured for clustermesh, use '--cluster-id' and '--cluster-name' with 'cilium install'. External workloads may still be configured.")
	}

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

	k.Log("✅ ClusterMesh disabled.")

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
	if err := k.params.validateParams(); err != nil {
		return err
	}

	if err := k.params.validateForEnable(); err != nil {
		return err
	}

	if err := k.GetClusterConfig(ctx); err != nil {
		return err
	}

	var err error
	k.imageVersion, err = k.client.GetRunningCiliumVersion(ctx, k.params.Namespace)
	if err != nil {
		return err
	}

	p, err := k.client.GetPlatform(ctx)
	if err != nil {
		return err
	}
	k.clusterArch = p.Arch

	svc, err := k.generateService()
	if err != nil {
		return err
	}

	_, err = k.client.GetDeployment(ctx, k.params.Namespace, defaults.ClusterMeshDeploymentName, metav1.GetOptions{})
	if err == nil {
		k.Log("✅ ClusterMesh is already enabled")
		return nil
	}

	if err := k.installCertificates(ctx); err != nil {
		return err
	}

	k.Log("✨ Deploying clustermesh-apiserver from %s...", k.apiserverImage())
	if _, err := k.client.CreateServiceAccount(ctx, k.params.Namespace, k8s.NewServiceAccount(defaults.ClusterMeshServiceAccountName), metav1.CreateOptions{}); err != nil {
		return err
	}

	if _, err := k.client.CreateClusterRole(ctx, clusterRole, metav1.CreateOptions{}); err != nil {
		return err
	}

	if _, err := k.client.CreateClusterRoleBinding(ctx, k8s.NewClusterRoleBinding(defaults.ClusterMeshClusterRoleName, k.params.Namespace, defaults.ClusterMeshServiceAccountName), metav1.CreateOptions{}); err != nil {
		return err
	}

	for i, opt := range k.params.ConfigOverwrites {
		if !strings.HasPrefix(opt, "--") {
			k.params.ConfigOverwrites[i] = "--" + opt
		}
	}

	if _, err := k.client.CreateDeployment(ctx, k.params.Namespace, k.generateDeployment(k.params.ConfigOverwrites), metav1.CreateOptions{}); err != nil {
		return err
	}

	if _, err := k.client.CreateService(ctx, k.params.Namespace, svc, metav1.CreateOptions{}); err != nil {
		return err
	}

	k.Log("✅ ClusterMesh enabled!")

	return nil
}

type accessInformation struct {
	ServiceType          corev1.ServiceType `json:"service_type,omitempty"`
	ServiceIPs           []string           `json:"service_ips,omitempty"`
	ServicePort          int                `json:"service_port,omitempty"`
	ClusterID            string             `json:"cluster_id,omitempty"`
	ClusterName          string             `json:"cluster_name,omitempty"`
	CA                   []byte             `json:"ca,omitempty"`
	ClientCert           []byte             `json:"client_cert,omitempty"`
	ClientKey            []byte             `json:"client_key,omitempty"`
	ExternalWorkloadCert []byte             `json:"external_workload_cert,omitempty"`
	ExternalWorkloadKey  []byte             `json:"external_workload_key,omitempty"`
	Tunnel               string             `json:"tunnel,omitempty"`
	MaxConnectedClusters int                `json:"max_connected_clusters,omitempty"`
}

func (ai *accessInformation) etcdConfiguration() string {
	cfg := "endpoints:\n"
	cfg += "- https://" + ai.ClusterName + ".mesh.cilium.io:" + fmt.Sprintf("%d", ai.ServicePort) + "\n"
	cfg += "trusted-ca-file: /var/lib/cilium/clustermesh/" + ai.ClusterName + caSuffix + "\n"
	cfg += "key-file: /var/lib/cilium/clustermesh/" + ai.ClusterName + keySuffix + "\n"
	cfg += "cert-file: /var/lib/cilium/clustermesh/" + ai.ClusterName + certSuffix + "\n"

	return cfg
}

func (ai *accessInformation) validate() bool {
	return ai.ClusterName != "" &&
		ai.ClusterName != "default" &&
		ai.ClusterID != "" &&
		ai.ClusterID != "0"
}

func getDeprecatedName(secretName string) string {
	switch secretName {
	case defaults.ClusterMeshRemoteSecretName:
		return defaults.ClusterMeshClientSecretName
	case defaults.ClusterMeshServerSecretName,
		defaults.ClusterMeshAdminSecretName,
		defaults.ClusterMeshClientSecretName,
		defaults.ClusterMeshExternalWorkloadSecretName:
		return secretName + "s"
	default:
		return ""
	}
}

func getExternalWorkloadCertName() string {
	if utils.IsInHelmMode() {
		return defaults.ClusterMeshClientSecretName
	}
	return defaults.ClusterMeshExternalWorkloadSecretName
}

// getDeprecatedSecret attempts to retrieve a secret using one or more deprecated names
// There are now multiple "layers" of deprecated secret names, so we call this function recursively if needed
func (k *K8sClusterMesh) getDeprecatedSecret(ctx context.Context, client k8sClusterMeshImplementation, secretName string, defaultName string) (*corev1.Secret, error) {

	deprecatedSecretName := getDeprecatedName(secretName)
	if deprecatedSecretName == "" {
		return nil, fmt.Errorf("unable to get secret %q and no deprecated names to try", secretName)
	}

	k.Log("Trying to get secret %s by deprecated name %s", secretName, deprecatedSecretName)

	secret, err := client.GetSecret(ctx, k.params.Namespace, deprecatedSecretName, metav1.GetOptions{})
	if err != nil {
		return k.getDeprecatedSecret(ctx, client, deprecatedSecretName, defaultName)
	}

	k.Log("⚠️ Deprecated secret name %q, should be changed to %q", secret.Name, defaultName)

	return secret, err
}

// We had inconsistency in naming clustermesh secrets between Helm installation and Cilium CLI installation
// Cilium CLI was naming clustermesh secrets with trailing 's'. eg. 'clustermesh-apiserver-client-certs' instead of `clustermesh-apiserver-client-cert`
// This caused Cilium CLI 'clustermesh status' command to fail when Cilium is installed using Helm
// getSecret handles both secret names and logs warning if deprecated secret name is found
func (k *K8sClusterMesh) getSecret(ctx context.Context, client k8sClusterMeshImplementation, secretName string) (*corev1.Secret, error) {

	secret, err := client.GetSecret(ctx, k.params.Namespace, secretName, metav1.GetOptions{})
	if err != nil {
		return k.getDeprecatedSecret(ctx, client, secretName, secretName)
	}
	return secret, err
}

func (k *K8sClusterMesh) getCACert(ctx context.Context, client k8sClusterMeshImplementation) ([]byte, error) {
	secret, err := client.GetSecret(ctx, k.params.Namespace, defaults.CASecretName, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("get secret %q to retrieve CA: %s", defaults.CASecretName, err)
	}

	// The helm and cronjob certificate generation methods currently store
	// the certificate under the ca.crt key, while cert-manager requires it
	// to be under the tls.crt key. Hence, let's attempt to retrieve it
	// using both keys.
	cert, ok := secret.Data[defaults.CASecretCertName]
	if ok {
		return cert, nil
	}

	cert, ok = secret.Data[corev1.TLSCertKey]
	if ok {
		return cert, nil
	}

	return nil, fmt.Errorf("secret %q does not contain the CA certificate", defaults.CASecretName)
}

func (k *K8sClusterMesh) extractAccessInformation(ctx context.Context, client k8sClusterMeshImplementation, endpoints []string, verbose bool, getExternalWorkLoadSecret bool) (*accessInformation, error) {
	cm, err := client.GetConfigMap(ctx, k.params.Namespace, defaults.ConfigMapName, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("unable to retrieve ConfigMap %q: %w", defaults.ConfigMapName, err)
	}

	if _, ok := cm.Data[configNameClusterName]; !ok {
		return nil, fmt.Errorf("%s is not set in ConfigMap %q", configNameClusterName, defaults.ConfigMapName)
	}

	clusterID := cm.Data[configNameClusterID]
	clusterName := cm.Data[configNameClusterName]

	if mcc, ok := cm.Data[configNameMaxConnectedClusters]; ok {
		maxConnectedClusters, err = strconv.Atoi(mcc)
		if err != nil {
			return nil, fmt.Errorf("unable to parse %s: %w", configNameMaxConnectedClusters, err)
		}
	}

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

	meshSecret, err := k.getSecret(ctx, client, defaults.ClusterMeshRemoteSecretName)
	if err != nil {
		return nil, fmt.Errorf("unable to get client secret to access clustermesh service: %w", err)
	}

	clientKey, ok := meshSecret.Data[corev1.TLSPrivateKeyKey]
	if !ok {
		return nil, fmt.Errorf("secret %q does not contain key %q", meshSecret.Name, corev1.TLSPrivateKeyKey)
	}

	clientCert, ok := meshSecret.Data[corev1.TLSCertKey]
	if !ok {
		return nil, fmt.Errorf("secret %q does not contain key %q", meshSecret.Name, corev1.TLSCertKey)
	}

	caCert, err := k.getCACert(ctx, client)
	// We failed to retrieve the CA from its own secret, let's fallback to the ca.crt certificate inside the mesh secret.
	if err != nil {
		caCert, ok = meshSecret.Data[defaults.CASecretCertName]
		if !ok {
			return nil, fmt.Errorf("unable to retrieve the CA certificate: %w", err)
		}
	}

	// ExternalWorkload secret is created by 'clustermesh enable' command, but it isn't created by Helm. We should try to load this secret only when needed
	var externalWorkloadKey, externalWorkloadCert []byte
	if getExternalWorkLoadSecret {
		externalWorkloadSecret, err := k.getSecret(ctx, client, getExternalWorkloadCertName())
		if err != nil {
			return nil, fmt.Errorf("unable to get external workload secret to access clustermesh service")
		}

		externalWorkloadKey, ok = externalWorkloadSecret.Data[corev1.TLSPrivateKeyKey]
		if !ok {
			return nil, fmt.Errorf("secret %q does not contain key %q", externalWorkloadSecret.Namespace, corev1.TLSPrivateKeyKey)
		}

		externalWorkloadCert, ok = externalWorkloadSecret.Data[corev1.TLSCertKey]
		if !ok {
			return nil, fmt.Errorf("secret %q does not contain key %q", externalWorkloadSecret.Namespace, corev1.TLSCertKey)
		}
	}

	tunnelProtocol := ""
	if cm.Data[configNameRoutingMode] == "tunnel" {
		// Cilium v1.14 and newer
		tunnelProtocol = "vxlan" // default for tunnel mode
		if proto, ok := cm.Data[configNameTunnelProtocol]; ok {
			tunnelProtocol = proto
		}
	} else if proto, ok := cm.Data[configNameTunnelLegacy]; ok {
		// Cilium v1.13 and older (some v1.14 configurations might use it too)
		// Can be removed once we drop support for v1.14
		tunnelProtocol = proto
	}

	ai := &accessInformation{
		ClusterID:            clusterID,
		ClusterName:          clusterName,
		CA:                   caCert,
		ClientKey:            clientKey,
		ClientCert:           clientCert,
		ExternalWorkloadKey:  externalWorkloadKey,
		ExternalWorkloadCert: externalWorkloadCert,
		ServiceType:          svc.Spec.Type,
		ServiceIPs:           []string{},
		Tunnel:               tunnelProtocol,
		MaxConnectedClusters: maxConnectedClusters,
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
			if ingressStatus.Hostname == "" {
				ai.ServiceIPs = append(ai.ServiceIPs, ingressStatus.IP)
			} else {
				k.Log("Hostname based ingress detected, trying to resolve it")

				ips, err := net.LookupHost(ingressStatus.Hostname)
				if err != nil {
					k.Log(fmt.Sprintf("Could not resolve the hostname of the ingress, falling back to the static IP. Error: %v", err))
					ai.ServiceIPs = append(ai.ServiceIPs, ingressStatus.IP)
				} else {
					k.Log("Hostname resolved, using the found ip(s)")
					ai.ServiceIPs = append(ai.ServiceIPs, ips...)
				}
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

// getClientsForConnect returns a k8s.Client for the local and remote cluster, respectively
func (k *K8sClusterMesh) getClientsForConnect() (*k8s.Client, *k8s.Client, error) {
	remoteClient, err := k8s.NewClient(k.params.DestinationContext, "", k.params.Namespace)
	if err != nil {
		return nil, nil, fmt.Errorf(
			"unable to create Kubernetes client to access remote cluster %q: %w",
			k.params.DestinationContext, err)
	}
	return k.client.(*k8s.Client), remoteClient, nil
}

func (k *K8sClusterMesh) shallowExtractAccessInfo(ctx context.Context, c *k8s.Client) (*accessInformation, error) {
	cm, err := c.GetConfigMap(ctx, k.params.Namespace, defaults.ConfigMapName, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("unable to retrieve ConfigMap %q: %w", defaults.ConfigMapName, err)
	}
	id, ok := cm.Data[configNameClusterID]
	if !ok {
		return nil, fmt.Errorf("unable to locate key: %q in ConfigMap %q", configNameClusterID, defaults.ConfigMapName)
	}
	name, ok := cm.Data[configNameClusterName]
	if !ok {
		return nil, fmt.Errorf("unable to locate key: %q in ConfigMap %q", configNameClusterName, defaults.ConfigMapName)
	}

	return &accessInformation{
		ClusterID:   id,
		ClusterName: name,
	}, nil
}

// connectAccessInit initializes a Kubernetes client for the local and remote cluster
// and performs some validation that the two clusters can be connected via clustermesh
func (k *K8sClusterMesh) getAccessInfoForConnect(
	ctx context.Context, localClient, remoteClient *k8s.Client,
) (*accessInformation, *accessInformation, error) {
	aiRemote, err := k.extractAccessInformation(ctx, remoteClient, k.params.DestinationEndpoints, true, false)
	if err != nil {
		k.Log("❌ Unable to retrieve access information of remote cluster %q: %s", remoteClient.ClusterName(), err)
		return nil, nil, err
	}

	aiLocal, err := k.extractAccessInformation(ctx, localClient, k.params.SourceEndpoints, true, false)
	if err != nil {
		k.Log("❌ Unable to retrieve access information of local cluster %q: %s", k.client.ClusterName(), err)
		return nil, nil, err
	}

	return aiLocal, aiRemote, nil
}

// connectAccessInit initializes a Kubernetes client for the local and remote cluster
// and performs some validation that the two clusters can be connected via clustermesh
func (k *K8sClusterMesh) validateInfoForConnect(aiLocal, aiRemote *accessInformation) error {
	if !aiRemote.validate() {
		return fmt.Errorf("remote cluster has non-unique name (%s) and/or ID (%s)",
			aiRemote.ClusterName, aiRemote.ClusterID)
	}

	if !aiLocal.validate() {
		return fmt.Errorf(
			"local cluster has the default name (cluster name: %s) and/or ID 0 (cluster ID: %s)",
			aiLocal.ClusterName, aiLocal.ClusterID)
	}

	cid, err := strconv.Atoi(aiRemote.ClusterID)
	if err != nil {
		return fmt.Errorf(
			"remote cluster has non-numeric cluster ID %s. Only numeric values 1-255 are allowed",
			aiRemote.ClusterID)
	}
	if cid < 1 || cid > aiLocal.MaxConnectedClusters {
		return fmt.Errorf("remote cluster has cluster ID %d out of acceptable range (1-%d)", cid, aiLocal.MaxConnectedClusters)
	}

	if aiRemote.MaxConnectedClusters != aiLocal.MaxConnectedClusters {
		return fmt.Errorf("remote and local clusters have different max connected clusters: %d != %d", aiRemote.MaxConnectedClusters, aiLocal.MaxConnectedClusters)
	}

	if aiRemote.ClusterName == aiLocal.ClusterName {
		return fmt.Errorf("remote and local cluster have the same, non-unique name: %s", aiLocal.ClusterName)
	}

	if aiRemote.ClusterID == aiLocal.ClusterID {
		return fmt.Errorf("remote and local cluster have the same, non-unique ID: %s", aiLocal.ClusterID)
	}

	return nil
}

func (k *K8sClusterMesh) Connect(ctx context.Context) error {
	localClient, remoteClient, err := k.getClientsForConnect()
	if err != nil {
		return err
	}

	aiLocal, aiRemote, err := k.getAccessInfoForConnect(ctx, localClient, remoteClient)
	if err != nil {
		return err
	}

	err = k.validateInfoForConnect(aiLocal, aiRemote)
	if err != nil {
		return err
	}

	k.Log("✨ Connecting cluster %s -> %s...", k.client.ClusterName(), remoteClient.ClusterName())
	if err := k.patchConfig(ctx, k.client, aiRemote); err != nil {
		return err
	}

	k.Log("✨ Connecting cluster %s -> %s...", remoteClient.ClusterName(), k.client.ClusterName())
	if err := k.patchConfig(ctx, remoteClient, aiLocal); err != nil {
		return err
	}

	k.Log("✅ Connected cluster %s and %s!", localClient.ClusterName(), remoteClient.ClusterName())

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
	remoteCluster, err := k8s.NewClient(k.params.DestinationContext, "", k.params.Namespace)
	if err != nil {
		return fmt.Errorf("unable to create Kubernetes client to access remote cluster %q: %w", k.params.DestinationContext, err)
	}

	if err := k.disconnectCluster(ctx, k.client, remoteCluster); err != nil {
		return err
	}

	if err := k.disconnectCluster(ctx, remoteCluster, k.client); err != nil {
		return err
	}

	k.Log("✅ Disconnected cluster %s and %s.", k.client.ClusterName(), remoteCluster.ClusterName())

	return nil
}

type Status struct {
	AccessInformation *accessInformation  `json:"access_information,omitempty"`
	Connectivity      *ConnectivityStatus `json:"connectivity,omitempty"`
}

func (k *K8sClusterMesh) statusAccessInformation(ctx context.Context, log bool, getExternalWorkloadSecret bool) (*accessInformation, error) {
	w := wait.NewObserver(ctx, wait.Parameters{Log: func(err error, wait string) {
		if log {
			k.Log("⌛ Waiting (%s) for access information: %s", wait, err)
		}
	}})
	defer w.Cancel()

	for {
		ai, err := k.extractAccessInformation(ctx, k.client, []string{}, false, getExternalWorkloadSecret)
		if err != nil && k.params.Wait {
			if err := w.Retry(err); err != nil {
				return nil, err
			}
			continue
		}

		return ai, err
	}
}

func (k *K8sClusterMesh) statusDeployment(ctx context.Context) (err error) {
	w := wait.NewObserver(ctx, wait.Parameters{Log: func(err error, wait string) {
		k.Log("⌛ Waiting (%s) for deployment %s to become ready: %s", wait, defaults.ClusterMeshDeploymentName, err)
	}})
	defer func() {
		w.Cancel()
		if err != nil {
			err = fmt.Errorf("deployment %s is not ready: %w", defaults.ClusterMeshDeploymentName, err)
		}
	}()

	for {
		err := k.client.CheckDeploymentStatus(ctx, k.params.Namespace, defaults.ClusterMeshDeploymentName)
		if err != nil && k.params.Wait {
			if err := w.Retry(err); err != nil {
				return err
			}
			continue
		}

		return err
	}
}

type StatisticalStatus struct {
	Min int64   `json:"min,omitempty"`
	Avg float64 `json:"avg,omitempty"`
	Max int64   `json:"max,omitempty"`
}

type ClusterStats struct {
	Configured int `json:"configured,omitempty"`
	Connected  int `json:"connected,omitempty"`
}

type ConnectivityStatus struct {
	GlobalServices StatisticalStatus        `json:"global_services,omitempty"`
	Connected      StatisticalStatus        `json:"connected,omitempty"`
	Clusters       map[string]*ClusterStats `json:"clusters,omitempty"`
	Total          int64                    `json:"total,omitempty"`
	NotReady       int64                    `json:"not_ready,omitempty"`
	Errors         status.ErrorCountMapMap  `json:"errors,omitempty"`
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

func remoteClusterStatusToError(status *models.RemoteCluster) error {
	switch {
	case status == nil:
		return errors.New("unknown status")
	case !status.Connected:
		return errors.New(status.Status)
	case status.Config == nil:
		return errors.New("remote cluster configuration retrieval status unknown")
	case status.Config.Required && !status.Config.Retrieved:
		return errors.New("remote cluster configuration required but not found")
	case status.Synced == nil:
		return errors.New("synchronization status unknown")
	case !(status.Synced.Nodes && status.Synced.Endpoints && status.Synced.Identities && status.Synced.Services):
		var toSync []string
		appendNotSynced := func(name string, synced bool) {
			if !synced {
				toSync = append(toSync, name)
			}
		}
		appendNotSynced("endpoints", status.Synced.Endpoints)
		appendNotSynced("identities", status.Synced.Identities)
		appendNotSynced("nodes", status.Synced.Nodes)
		appendNotSynced("services", status.Synced.Services)

		return fmt.Errorf("synchronization in progress for %s", strings.Join(toSync, ", "))
	default:
		return errors.New("not ready")
	}
}

func (c *ConnectivityStatus) parseAgentStatus(name string, expected []string, s *status.ClusterMeshAgentConnectivityStatus) {
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
			c.addError(name, cluster.Name, remoteClusterStatusToError(cluster))
		}
	}

	// Add an error for any cluster that was expected but not found
	var missing bool
	for _, exp := range expected {
		if _, ok := s.Clusters[exp]; !ok {
			missing = true
			c.addError(name, exp, errors.New("unknown status"))
		}
	}

	if missing || ready != int64(len(s.Clusters)) {
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
	w := wait.NewObserver(ctx, wait.Parameters{Log: func(err error, wait string) {
		k.Log("⌛ Waiting (%s) for clusters to be connected: %s", wait, err)
	}})
	defer w.Cancel()

	for {
		status, err := k.determineStatusConnectivity(ctx)
		if k.params.Wait {
			if err == nil {
				if status.NotReady > 0 {
					err = fmt.Errorf("%d nodes are not ready", status.NotReady)
				}
			}

			if err != nil {
				if err := w.Retry(err); err != nil {
					return status, err
				}
				continue
			}
		}

		return status, err
	}
}

func (k *K8sClusterMesh) determineStatusConnectivity(ctx context.Context) (*ConnectivityStatus, error) {
	stats := &ConnectivityStatus{
		GlobalServices: StatisticalStatus{Min: -1},
		Connected:      StatisticalStatus{Min: -1},
		Errors:         status.ErrorCountMapMap{},
		Clusters:       map[string]*ClusterStats{},
	}

	// Retrieve the remote clusters to connect to from the clustermesh configuration,
	// as there's no guarantee that the secret has already propagated into the agents.
	// Don't fail in case the secret is not found, as it is legitimate if no cluster
	// has been connected yet.
	config, err := k.client.GetSecret(ctx, k.params.Namespace, defaults.ClusterMeshSecretName, metav1.GetOptions{})
	if err != nil && !k8serrors.IsNotFound(err) {
		return nil, fmt.Errorf("unable to retrieve clustermesh configuration: %w", err)
	}

	var expected []string
	for name, cfg := range config.Data {
		// Same check as https://github.com/cilium/cilium/blob/538a18800206da0d33916f5f48853a3d4454dd81/pkg/clustermesh/internal/config.go#L68
		// Additionally skip the configuration of the local cluster, if present
		if name != k.clusterName && strings.Contains(string(cfg), "endpoints:") {
			stats.Clusters[name] = &ClusterStats{}
			expected = append(expected, name)
		}
	}

	pods, err := k.client.ListPods(ctx, k.params.Namespace, metav1.ListOptions{LabelSelector: defaults.AgentPodSelector})
	if err != nil {
		return nil, fmt.Errorf("unable to list cilium pods: %w", err)
	}

	for _, pod := range pods.Items {
		s, err := k.statusCollector.ClusterMeshConnectivity(ctx, pod.Name)
		if err != nil {
			if len(expected) == 0 && errors.Is(err, status.ErrClusterMeshStatusNotAvailable) {
				continue
			}
			return nil, fmt.Errorf("unable to determine status of cilium pod %q: %w", pod.Name, err)
		}

		stats.parseAgentStatus(pod.Name, expected, s)
	}

	if len(pods.Items) > 0 {
		stats.GlobalServices.Avg /= float64(len(pods.Items))
		stats.Connected.Avg /= float64(len(pods.Items))
	}

	return stats, nil
}

func (k *K8sClusterMesh) Status(ctx context.Context) (*Status, error) {
	err := k.GetClusterConfig(ctx)
	if err != nil {
		return nil, err
	}

	collector, err := status.NewK8sStatusCollector(k.client, status.K8sStatusParameters{
		Namespace: k.params.Namespace,
	})
	if err != nil {
		return nil, fmt.Errorf("unable to create client to collect status: %w", err)
	}

	k.statusCollector = collector

	ctx, cancel := context.WithTimeout(ctx, k.params.waitTimeout())
	defer cancel()

	s := &Status{}

	if k.externalKVStore {
		k.Log("✅ Cilium is configured with an external kvstore")
	} else {
		s.AccessInformation, err = k.statusAccessInformation(ctx, true, false)
		if err != nil {
			return nil, err
		}

		k.Log("✅ Service %q of type %q found", defaults.ClusterMeshServiceName, s.AccessInformation.ServiceType)
		k.Log("✅ Cluster access information is available:")
		for _, ip := range s.AccessInformation.ServiceIPs {
			k.Log("  - %s:%d", ip, s.AccessInformation.ServicePort)
		}

		err = k.statusDeployment(ctx)
		if err != nil {
			return nil, err
		}
		k.Log("✅ Deployment %s is ready", defaults.ClusterMeshDeploymentName)
	}

	s.Connectivity, err = k.statusConnectivity(ctx)

	if k.params.Output == status.OutputJSON {
		jsonStatus, err := json.MarshalIndent(s, "", " ")
		if err != nil {
			return nil, fmt.Errorf("failed to marshal status to JSON")
		}
		fmt.Println(string(jsonStatus))
		return s, nil
	}

	if s.Connectivity != nil {
		if s.Connectivity.NotReady > 0 {
			k.Log("⚠️  %d/%d nodes are not connected to all clusters [min:%d / avg:%.1f / max:%d]",
				s.Connectivity.NotReady,
				s.Connectivity.Total,
				s.Connectivity.Connected.Min,
				s.Connectivity.Connected.Avg,
				s.Connectivity.Connected.Max)
		} else if len(s.Connectivity.Clusters) > 0 {
			k.Log("✅ All %d nodes are connected to all clusters [min:%d / avg:%.1f / max:%d]",
				s.Connectivity.Total,
				s.Connectivity.Connected.Min,
				s.Connectivity.Connected.Avg,
				s.Connectivity.Connected.Max)
		}

		if len(s.Connectivity.Clusters) > 0 {
			k.Log("🔌 Cluster Connections:")
			clusters := maps.Keys(s.Connectivity.Clusters)
			sort.Strings(clusters)
			for _, cluster := range clusters {
				stats := s.Connectivity.Clusters[cluster]
				k.Log("  - %s: %d/%d configured, %d/%d connected",
					cluster, stats.Configured, s.Connectivity.Total,
					stats.Connected, s.Connectivity.Total)
			}
		} else {
			k.Log("🔌 No cluster connected")
		}

		k.Log("🔀 Global services: [ min:%d / avg:%.1f / max:%d ]",
			s.Connectivity.GlobalServices.Min,
			s.Connectivity.GlobalServices.Avg,
			s.Connectivity.GlobalServices.Max)

		if len(s.Connectivity.Errors) > 0 {
			k.Log("❌ %d Errors:", len(s.Connectivity.Errors))

			podNames := maps.Keys(s.Connectivity.Errors)
			sort.Strings(podNames)
			for _, podName := range podNames {
				clusters := s.Connectivity.Errors[podName]
				for clusterName, a := range clusters {
					for _, err := range a.Errors {
						k.Log("  ❌ %s is not connected to cluster %s: %s", podName, clusterName, err)
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
	} else {
		k.Log("ℹ️  No external workload resources to remove.")
	}
	if len(errs) > 0 {
		return errors.New(strings.Join(errs, ", "))
	}
	return nil
}

var installScriptFmt = `#!/bin/bash
CILIUM_IMAGE=${1:-%[1]s}
CLUSTER_ADDR=${2:-%[2]s}
CONFIG_OVERWRITES=${3:-%[3]s}

set -e
shopt -s extglob

# Run without sudo if not available (e.g., running as root)
SUDO=
if [ ! "$(whoami)" = "root" ] ; then
    SUDO=sudo
fi

if [ "$1" = "uninstall" ] ; then
    if [ -n "$(${SUDO} docker ps -a -q -f name=cilium)" ]; then
        echo "Shutting down running Cilium agent"
        ${SUDO} docker rm -f cilium || true
    fi
    if [ -e /usr/bin/cilium ]; then
        echo "Removing /usr/bin/cilium"
        ${SUDO} rm /usr/bin/cilium
    fi
    if [ -e /usr/bin/cilium-dbg ] ; then
        echo "Removing /usr/bin/cilium-dbg"
        ${SUDO} rm /usr/bin/cilium-dbg
    fi
    pushd /etc
    if [ -f resolv.conf.orig ] ; then
        echo "Restoring /etc/resolv.conf"
        ${SUDO} mv -f resolv.conf.orig resolv.conf
    elif [ -f resolv.conf.link ] && [ -f $(cat resolv.conf.link) ] ; then
        echo "Restoring systemd resolved config..."
        if [ -f /usr/lib/systemd/resolved.conf.d/cilium-kube-dns.conf ] ; then
	    ${SUDO} rm /usr/lib/systemd/resolved.conf.d/cilium-kube-dns.conf
        fi
        ${SUDO} systemctl daemon-reload
        ${SUDO} systemctl reenable systemd-resolved.service
        ${SUDO} service systemd-resolved restart
        ${SUDO} ln -fs $(cat resolv.conf.link) resolv.conf
        ${SUDO} rm resolv.conf.link
    fi
    popd
    exit 0
fi

if [ -z "$CLUSTER_ADDR" ] ; then
    echo "CLUSTER_ADDR must be defined to the IP:PORT at which the clustermesh-apiserver is reachable."
    exit 1
fi

port='@(6553[0-5]|655[0-2][0-9]|65[0-4][0-9][0-9]|6[0-4][0-9][0-9][0-9]|[1-5][0-9][0-9][0-9][0-9]|[1-9][0-9][0-9][0-9]|[1-9][0-9][0-9]|[1-9][0-9]|[1-9])'
byte='@(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])'
ipv4="$byte\.$byte\.$byte\.$byte"

# Default port is for a HostPort service
case "$CLUSTER_ADDR" in
    \[+([0-9a-fA-F:])\]:$port)
	CLUSTER_PORT=${CLUSTER_ADDR##\[*\]:}
	CLUSTER_IP=${CLUSTER_ADDR#\[}
	CLUSTER_IP=${CLUSTER_IP%%\]:*}
	;;
    $ipv4:$port)
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

${SUDO} mkdir -p /var/lib/cilium/etcd
${SUDO} tee /var/lib/cilium/etcd/ca.crt <<EOF >/dev/null
%[4]sEOF
${SUDO} tee /var/lib/cilium/etcd/tls.crt <<EOF >/dev/null
%[5]sEOF
${SUDO} tee /var/lib/cilium/etcd/tls.key <<EOF >/dev/null
%[6]sEOF
${SUDO} tee /var/lib/cilium/etcd/config.yaml <<EOF >/dev/null
---
trusted-ca-file: /var/lib/cilium/etcd/ca.crt
cert-file: /var/lib/cilium/etcd/tls.crt
key-file: /var/lib/cilium/etcd/tls.key
endpoints:
- https://clustermesh-apiserver.cilium.io:$CLUSTER_PORT
EOF

CILIUM_OPTS=" --join-cluster %[8]s --enable-endpoint-health-checking=false"
CILIUM_OPTS+=" --cluster-name ${CLUSTER_NAME:-%[9]s} --cluster-id ${CLUSTER_ID:-%[10]s}"
CILIUM_OPTS+=" --kvstore etcd --kvstore-opt etcd.config=/var/lib/cilium/etcd/config.yaml"
if [ -n "$HOST_IP" ] ; then
    CILIUM_OPTS+=" --ipv4-node $HOST_IP"
fi
if [ -n "$CONFIG_OVERWRITES" ] ; then
    CILIUM_OPTS+=" $CONFIG_OVERWRITES"
fi

DOCKER_OPTS=" -d --log-driver local --restart always"
DOCKER_OPTS+=" --privileged --network host --cap-add NET_ADMIN --cap-add SYS_MODULE"
# Run cilium agent in the host's cgroup namespace so that
# socket-based load balancing works as expected.
# See https://github.com/cilium/cilium/pull/16259 for more details.
DOCKER_OPTS+=" --cgroupns=host"
DOCKER_OPTS+=" --volume /var/lib/cilium/etcd:/var/lib/cilium/etcd"
DOCKER_OPTS+=" --volume /var/run/cilium:/var/run/cilium"
DOCKER_OPTS+=" --volume /boot:/boot"
DOCKER_OPTS+=" --volume /lib/modules:/lib/modules"
DOCKER_OPTS+=" --volume /sys/fs/bpf:/sys/fs/bpf"
DOCKER_OPTS+=" --volume /run/xtables.lock:/run/xtables.lock"
DOCKER_OPTS+=" --add-host clustermesh-apiserver.cilium.io:$CLUSTER_IP"

cilium_started=false
retries=%[7]s
while [ $cilium_started = false ]; do
    if [ -n "$(${SUDO} docker ps -a -q -f name=cilium)" ]; then
        echo "Shutting down running Cilium agent"
        ${SUDO} docker rm -f cilium || true
    fi

    echo "Launching Cilium agent $CILIUM_IMAGE..."
    ${SUDO} docker run --name cilium $DOCKER_OPTS $CILIUM_IMAGE cilium-agent $CILIUM_OPTS

    # Copy Cilium CLI
    ${SUDO} docker cp -L cilium:/usr/bin/cilium /usr/bin/cilium-dbg
    ${SUDO} ln -fs /usr/bin/cilium-dbg /usr/bin/cilium

    # Wait for cilium agent to become available
    for ((i = 0 ; i < 12; i++)); do
        if ${SUDO} cilium-dbg status --brief > /dev/null 2>&1; then
            cilium_started=true
            break
        fi
        sleep 5s
        echo "Waiting for Cilium daemon to come up..."
    done

    echo "Cilium status:"
    ${SUDO} cilium-dbg status || true

    if [ "$cilium_started" = true ] ; then
        echo 'Cilium successfully started!'
    else
        if [ $retries -eq 0 ]; then
            >&2 echo 'Timeout waiting for Cilium to start, retries exhausted.'
            exit 1
        fi
        ((retries--))
        echo "Restarting Cilium..."
    fi
done

# Wait for kube-dns service to become available
kubedns=""
for ((i = 0 ; i < 24; i++)); do
    kubedns=$(${SUDO} cilium-dbg service list get -o jsonpath='{[?(@.spec.frontend-address.port==53)].spec.frontend-address.ip}')
    if [ -n "$kubedns" ] ; then
        break
    fi
    sleep 5s
    echo "Waiting for kube-dns service to come available..."
done

namespace=$(${SUDO} cilium-dbg endpoint get -l reserved:host -o jsonpath='{$[0].status.identity.labels}' | tr -d "[]\"" | tr "," "\n" | grep io.kubernetes.pod.namespace | cut -d= -f2)

if [ -n "$kubedns" ] ; then
    if grep "nameserver $kubedns" /etc/resolv.conf ; then
	echo "kube-dns IP $kubedns already in /etc/resolv.conf"
    else
	linkval=$(readlink /etc/resolv.conf) && echo "$linkval" | ${SUDO} tee /etc/resolv.conf.link || true
	if [[ "$linkval" == *"/systemd/"* ]] ; then
	    echo "updating systemd resolved with kube-dns IP $kubedns"
	    ${SUDO} mkdir -p /usr/lib/systemd/resolved.conf.d
	    ${SUDO} tee /usr/lib/systemd/resolved.conf.d/cilium-kube-dns.conf <<EOF >/dev/null
# This file is installed by Cilium to use kube dns server from a non-k8s node.
[Resolve]
DNS=$kubedns
Domains=${namespace}.svc.cluster.local svc.cluster.local cluster.local
EOF
	    ${SUDO} systemctl daemon-reload
	    ${SUDO} systemctl reenable systemd-resolved.service
	    ${SUDO} service systemd-resolved restart
	    ${SUDO} ln -fs /run/systemd/resolve/resolv.conf /etc/resolv.conf
	else
	    echo "Adding kube-dns IP $kubedns to /etc/resolv.conf"
	    ${SUDO} cp /etc/resolv.conf /etc/resolv.conf.orig
	    resolvconf="nameserver $kubedns\n$(cat /etc/resolv.conf)\nsearch ${namespace}.svc.cluster.local svc.cluster.local cluster.local\n"
	    printf "$resolvconf" | ${SUDO} tee /etc/resolv.conf
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
		return fmt.Errorf("DaemonSet %s is not available", defaults.AgentDaemonSetName)
	}
	k.Log("✅ Using image from Cilium DaemonSet: %s", daemonSet.Spec.Template.Spec.Containers[0].Image)

	ai, err := k.statusAccessInformation(ctx, false, true)
	if err != nil {
		return err
	}
	if ai.Tunnel != "" && ai.Tunnel != "vxlan" {
		return fmt.Errorf("datapath not using vxlan, please install Cilium with '--set tunnelMode=vxlan'")
	}

	clusterAddr := fmt.Sprintf("%s:%d", ai.ServiceIPs[0], ai.ServicePort)
	k.Log("✅ Using clustermesh-apiserver service address: %s", clusterAddr)

	configOverwrites := ""
	if len(k.params.ConfigOverwrites) > 0 {
		for i, opt := range k.params.ConfigOverwrites {
			if !strings.HasPrefix(opt, "--") {
				k.params.ConfigOverwrites[i] = "--" + opt
			}
		}
		configOverwrites = strings.Join(k.params.ConfigOverwrites, " ")
	}

	if k.params.Retries <= 0 {
		k.params.Retries = 1
	}

	sockLBOpt := "--bpf-lb-sock"
	fmt.Fprintf(writer, installScriptFmt,
		daemonSet.Spec.Template.Spec.Containers[0].Image, clusterAddr,
		configOverwrites,
		string(ai.CA), string(ai.ExternalWorkloadCert), string(ai.ExternalWorkloadKey),
		strconv.Itoa(k.params.Retries), sockLBOpt, ai.ClusterName, ai.ClusterID)
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
	collector, err := status.NewK8sStatusCollector(k.client, status.K8sStatusParameters{
		Namespace: k.params.Namespace,
	})
	if err != nil {
		return fmt.Errorf("unable to create client to collect status: %w", err)
	}

	k.statusCollector = collector

	ctx, cancel := context.WithTimeout(ctx, k.params.waitTimeout())
	defer cancel()

	ai, err := k.statusAccessInformation(ctx, true, true)
	if err != nil {
		return err
	}

	k.Log("✅ Service %q of type %q found", defaults.ClusterMeshServiceName, ai.ServiceType)
	k.Log("✅ Cluster access information is available:")
	for _, ip := range ai.ServiceIPs {
		k.Log("	 - %s:%d", ip, ai.ServicePort)
	}

	var cews []ciliumv2.CiliumExternalWorkload

	if len(names) == 0 {
		cewList, err := k.client.ListCiliumExternalWorkloads(ctx, metav1.ListOptions{})
		if err != nil {
			return err
		}
		cews = cewList.Items
		if len(cews) == 0 {
			k.Log("⚠️ No external workloads found.")
			return nil
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

func log(format string, a ...interface{}) {
	// TODO (ajs): make logger configurable
	fmt.Fprintf(os.Stdout, format+"\n", a...)
}

func generateEnableHelmValues(params Parameters, flavor k8s.Flavor) (map[string]interface{}, error) {
	helmVals := map[string]interface{}{
		"clustermesh": map[string]interface{}{
			"useAPIServer": true,
		},
		"externalWorkloads": map[string]interface{}{
			"enabled": params.EnableExternalWorkloads,
		},
	}

	if params.ServiceType == "" {
		switch flavor.Kind {
		case k8s.KindGKE:
			log("🔮 Auto-exposing service within GCP VPC (cloud.google.com/load-balancer-type=Internal)")
			helmVals["clustermesh"].(map[string]interface{})["apiserver"] = map[string]interface{}{
				"service": map[string]interface{}{
					"type": corev1.ServiceTypeLoadBalancer,
					"annotations": map[string]interface{}{
						"cloud.google.com/load-balancer-type": "Internal",
						// Allows cross-region access
						"networking.gke.io/internal-load-balancer-allow-global-access": "true",
					},
				},
			}
		case k8s.KindAKS:
			log("🔮 Auto-exposing service within Azure VPC (service.beta.kubernetes.io/azure-load-balancer-internal)")
			helmVals["clustermesh"].(map[string]interface{})["apiserver"] = map[string]interface{}{
				"service": map[string]interface{}{
					"type": corev1.ServiceTypeLoadBalancer,
					"annotations": map[string]interface{}{
						"service.beta.kubernetes.io/azure-load-balancer-internal": "true",
					},
				},
			}
		case k8s.KindEKS:
			log("🔮 Auto-exposing service within AWS VPC (service.beta.kubernetes.io/aws-load-balancer-internal: 0.0.0.0/0")
			helmVals["clustermesh"].(map[string]interface{})["apiserver"] = map[string]interface{}{
				"service": map[string]interface{}{
					"type": corev1.ServiceTypeLoadBalancer,
					"annotations": map[string]interface{}{
						"service.beta.kubernetes.io/aws-load-balancer-internal": "0.0.0.0/0",
					},
				},
			}
		default:
			return nil, fmt.Errorf("cannot auto-detect service type, please specify using '--service-type' option")
		}
	} else {
		if corev1.ServiceType(params.ServiceType) == corev1.ServiceTypeNodePort {
			log("⚠️  Using service type NodePort may fail when nodes are removed from the cluster!")
		}
		helmVals["clustermesh"].(map[string]interface{})["apiserver"] = map[string]interface{}{
			"service": map[string]interface{}{
				"type": params.ServiceType,
			},
		}
	}

	helmVals["clustermesh"].(map[string]interface{})["apiserver"].(map[string]interface{})["tls"] =
		// default to using certgen, so that certificates are renewed automatically
		map[string]interface{}{
			"auto": map[string]interface{}{
				"enabled": true,
				"method":  "cronJob",
				// run the renewal every 4 months on the 1st of the month
				"schedule": "0 0 1 */4 *",
			},
		}

	helmVals["clustermesh"].(map[string]interface{})["apiserver"].(map[string]interface{})["kvstoremesh"] =
		map[string]interface{}{
			"enabled": params.EnableKVStoreMesh,
		}

	return helmVals, nil
}

func EnableWithHelm(ctx context.Context, k8sClient *k8s.Client, params Parameters) error {
	helmVals, err := generateEnableHelmValues(params, k8sClient.AutodetectFlavor(ctx))
	if err != nil {
		return err
	}
	upgradeParams := helm.UpgradeParameters{
		Namespace:   params.Namespace,
		Name:        defaults.HelmReleaseName,
		Values:      helmVals,
		ResetValues: false,
		ReuseValues: true,
	}
	_, err = helm.Upgrade(ctx, k8sClient.HelmActionConfig, upgradeParams)
	return err
}

func DisableWithHelm(ctx context.Context, k8sClient *k8s.Client, params Parameters) error {
	helmStrValues := []string{
		"clustermesh.useAPIServer=false",
		"externalWorkloads.enabled=false",
	}
	vals, err := helm.ParseVals(helmStrValues)
	if err != nil {
		return err
	}
	upgradeParams := helm.UpgradeParameters{
		Namespace:   params.Namespace,
		Name:        defaults.HelmReleaseName,
		Values:      vals,
		ResetValues: false,
		ReuseValues: true,
	}
	_, err = helm.Upgrade(ctx, k8sClient.HelmActionConfig, upgradeParams)
	return err
}

func getRelease(kc *k8s.Client) (*release.Release, error) {
	return kc.HelmActionConfig.Releases.Last(defaults.HelmReleaseName)
}

// validateCAMatch determines if the certificate authority certificate being
// used by aiLocal and aiRemote uses a matching keypair. The bool return value
// is true (keypairs match), false (keys do not match OR there was an error)
func (k *K8sClusterMesh) validateCAMatch(aiLocal, aiRemote *accessInformation) (bool, error) {
	caLocal := aiLocal.CA
	block, _ := pem.Decode(caLocal)
	if block == nil {
		return false, fmt.Errorf("failed to parse certificate PEM for local CA cert")
	}
	localCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return false, err
	}

	caRemote := aiRemote.CA
	block, _ = pem.Decode(caRemote)
	if block == nil {
		return false, fmt.Errorf("failed to parse certificate PEM for remote CA cert")
	}
	remoteCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return false, err
	}

	// Compare the x509 key identifier of each certificate
	if !bytes.Equal(localCert.SubjectKeyId, remoteCert.SubjectKeyId) {
		// Note: For now, do NOT return an error. Warn about this condition at the call site.
		return false, nil
	}
	return true, nil
}

// ConnectWithHelm enables clustermesh using a Helm Upgrade
// action. Certificates are generated via the Helm chart's cronJob
// (certgen) mode. As with classic mode, only autodetected IP-based
// clustermesh-apiserver Service endpoints are currently supported.
func (k *K8sClusterMesh) ConnectWithHelm(ctx context.Context) error {
	localRelease, err := getRelease(k.client.(*k8s.Client))
	if err != nil {
		k.Log("❌ Unable to find Helm release for the target cluster")
		return err
	}

	ok, err := k.needsClassicMode(localRelease)
	if err != nil {
		return err
	}
	if ok {
		return k.Connect(ctx)
	}

	localClient, remoteClient, err := k.getClientsForConnect()
	if err != nil {
		return err
	}

	aiLocal, aiRemote, err := k.getAccessInfoForConnect(ctx, localClient, remoteClient)
	if err != nil {
		return err
	}

	err = k.validateInfoForConnect(aiLocal, aiRemote)
	if err != nil {
		return err
	}

	// Validate that CA certificates match between the two clusters
	match, err := k.validateCAMatch(aiLocal, aiRemote)
	if err != nil {
		return err
	} else if !match {
		k.Log("⚠️ Cilium CA certificates do not match between clusters. Multicluster features will be limited!")
	}

	// Get existing helm values for the local cluster
	localHelmValues := localRelease.Config
	// Expand those values to include the clustermesh configuration
	localHelmValues, err = updateClustermeshConfig(localHelmValues, aiRemote, !match)
	if err != nil {
		return err
	}

	// Get existing helm values for the remote cluster
	remoteRelease, err := getRelease(remoteClient)
	if err != nil {
		k.Log("❌ Unable to find Helm release for the remote cluster")
		return err
	}
	remoteHelmValues := remoteRelease.Config
	// Expand those values to include the clustermesh configuration
	remoteHelmValues, err = updateClustermeshConfig(remoteHelmValues, aiLocal, !match)
	if err != nil {
		return err
	}

	upgradeParams := helm.UpgradeParameters{
		Namespace:   k.params.Namespace,
		Name:        defaults.HelmReleaseName,
		Values:      localHelmValues,
		ResetValues: false,
		ReuseValues: true,
	}

	// Enable clustermesh using a Helm Upgrade command against our target cluster
	k.Log("ℹ️ Configuring Cilium in cluster '%s' to connect to cluster '%s'",
		localClient.ClusterName(), remoteClient.ClusterName())
	_, err = helm.Upgrade(ctx, localClient.HelmActionConfig, upgradeParams)
	if err != nil {
		return err
	}

	// Enable clustermesh using a Helm Upgrade command against the remote cluster
	k.Log("ℹ️ Configuring Cilium in cluster '%s' to connect to cluster '%s'",
		remoteClient.ClusterName(), localClient.ClusterName())
	upgradeParams.Values = remoteHelmValues
	_, err = helm.Upgrade(ctx, remoteClient.HelmActionConfig, upgradeParams)
	if err != nil {
		return err
	}

	k.Log("✅ Connected cluster %s and %s!", localClient.ClusterName(), remoteClient.ClusterName())
	return nil
}

// Helm-based clustermesh connect/disconnect is only supported on Cilium
// v1.14+ due to a lack of support in earlier versions for
// autoconfigured certificates (tls.{crt,key}) for cluster
// members when running in certgen (cronJob) PKI mode
func (k *K8sClusterMesh) needsClassicMode(r *release.Release) (bool, error) {
	if r == nil {
		return false, fmt.Errorf("needs a valid helm release. got nil")
	}

	version := r.Chart.AppVersion()
	semv, err := utils.ParseCiliumVersion(version)
	if err != nil {
		return false, fmt.Errorf("failed to parse Cilium version: %w", err)
	}
	k.Log("✅ Detected Helm release with Cilium version %s", semv)

	const ciliumHelmMinRev = "1.14.0"
	cv := semver.MustParse(ciliumHelmMinRev)
	if semv.Major == cv.Major && semv.Minor < cv.Minor {
		k.Log("⚠️ Cilium Version is less than %s. Continuing in classic mode.", ciliumHelmMinRev)
		return true, nil
	}

	return false, nil
}

func (k *K8sClusterMesh) DisconnectWithHelm(ctx context.Context) error {
	localRelease, err := getRelease(k.client.(*k8s.Client))
	if err != nil {
		k.Log("❌ Unable to find Helm release for the target cluster")
		return err
	}
	ok, err := k.needsClassicMode(localRelease)
	if err != nil {
		return err
	}
	if ok {
		return k.Disconnect(ctx)
	}

	localClient, remoteClient, err := k.getClientsForConnect()
	if err != nil {
		return err
	}
	aiLocal, err := k.shallowExtractAccessInfo(ctx, localClient)
	if err != nil {
		return err
	}
	aiRemote, err := k.shallowExtractAccessInfo(ctx, remoteClient)
	if err != nil {
		return err
	}

	// Modify the clustermesh config to remove the intended cluster if any
	localHelmValues, err := removeFromClustermeshConfig(localRelease.Config, aiRemote.ClusterName)
	if err != nil {
		return err
	}

	// Get existing helm values for the remote cluster
	remoteRelease, err := getRelease(remoteClient)
	if err != nil {
		k.Log("❌ Unable to find Helm release for the remote cluster")
		return err
	}
	// Modify the clustermesh config to remove the intended cluster if any
	remoteHelmValues, err := removeFromClustermeshConfig(remoteRelease.Config, aiLocal.ClusterName)
	if err != nil {
		return err
	}

	upgradeParams := helm.UpgradeParameters{
		Namespace:   k.params.Namespace,
		Name:        defaults.HelmReleaseName,
		Values:      localHelmValues,
		ResetValues: false,
		ReuseValues: true,
	}

	// Disconnect clustermesh using a Helm Upgrade command against our target cluster
	k.Log("ℹ️ Configuring Cilium in cluster '%s' to disconnect from cluster '%s'",
		localClient.ClusterName(), remoteClient.ClusterName())
	if _, err = helm.Upgrade(ctx, localClient.HelmActionConfig, upgradeParams); err != nil {
		return err
	}

	// Disconnect clustermesh using a Helm Upgrade command against the remote cluster
	k.Log("ℹ️ Configuring Cilium in cluster '%s' to disconnect from cluster '%s'",
		remoteClient.ClusterName(), localClient.ClusterName())
	upgradeParams.Values = remoteHelmValues
	if _, err = helm.Upgrade(ctx, remoteClient.HelmActionConfig, upgradeParams); err != nil {
		return err
	}
	k.Log("✅ Disconnected clusters %s and %s!", localClient.ClusterName(), remoteClient.ClusterName())

	return nil
}

func updateClustermeshConfig(
	values map[string]interface{}, aiRemote *accessInformation, configTLS bool,
) (map[string]interface{}, error) {
	// get current clusters config slice, if it exists
	c, found, err := unstructured.NestedFieldCopy(values, "clustermesh", "config", "clusters")
	if err != nil {
		return nil, fmt.Errorf("existing clustermesh.config is invalid")
	}
	if !found || c == nil {
		c = []interface{}{}
	}

	// parse the existing config slice
	oldClusters := make([]map[string]interface{}, 0)
	cs, ok := c.([]interface{})
	if !ok {
		return nil, fmt.Errorf("existing clustermesh.config.clusters array is invalid")
	}
	for _, m := range cs {
		cluster, ok := m.(map[string]interface{})
		if !ok {
			return nil, fmt.Errorf("existing clustermesh.config.clusters array is invalid")
		}
		oldClusters = append(oldClusters, cluster)
	}

	remoteCluster := map[string]interface{}{
		"name": aiRemote.ClusterName,
		"ips":  []string{aiRemote.ServiceIPs[0]},
		"port": aiRemote.ServicePort,
	}

	// Only add TLS configuration if requested (probably because CA
	// certs do not match among clusters). Note that this is a DEGRADED
	// mode of operation in which client certificates will not be
	// renewed automatically and cross-cluster Hubble does not operate.
	if configTLS {
		remoteCluster["tls"] = map[string]interface{}{
			"cert":   base64.StdEncoding.EncodeToString(aiRemote.ClientCert),
			"key":    base64.StdEncoding.EncodeToString(aiRemote.ClientKey),
			"caCert": base64.StdEncoding.EncodeToString(aiRemote.CA),
		}
	}

	// allocate new cluster entries
	newClusters := []map[string]interface{}{remoteCluster}

	// merge new clusters on top of old clusters
	clusters := map[string]map[string]interface{}{}
	for _, c := range oldClusters {
		name, ok := c["name"].(string)
		if !ok {
			return nil, fmt.Errorf("existing clustermesh.config.clusters array is invalid")
		}
		clusters[name] = c
	}
	for _, c := range newClusters {
		clusters[c["name"].(string)] = c
	}

	outputClusters := make([]map[string]interface{}, 0)
	for _, v := range clusters {
		outputClusters = append(outputClusters, v)
	}

	newValues := map[string]interface{}{
		"clustermesh": map[string]interface{}{
			"config": map[string]interface{}{
				"enabled":  true,
				"clusters": outputClusters,
			},
		},
	}

	return newValues, nil
}

func removeFromClustermeshConfig(values map[string]any, clusterName string) (map[string]any, error) {
	// get current clusters config slice, if it exists
	c, found, err := unstructured.NestedFieldCopy(values, "clustermesh", "config", "clusters")
	if err != nil {
		return nil, fmt.Errorf("existing clustermesh.config is invalid")
	}
	if !found || c == nil {
		c = []any{}
	}

	cs, ok := c.([]any)
	if !ok {
		return nil, fmt.Errorf("existing clustermesh.config.clusters array is invalid")
	}
	outputClusters := make([]map[string]any, 0, len(cs))
	for _, m := range cs {
		cluster, ok := m.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("existing clustermesh.config.clusters map is invalid")
		}
		name, ok := cluster["name"].(string)
		if ok && name == clusterName {
			continue
		}
		outputClusters = append(outputClusters, cluster)
	}

	newValues := map[string]any{
		"clustermesh": map[string]any{
			"config": map[string]any{
				"enabled":  true,
				"clusters": outputClusters,
			},
		},
	}

	return newValues, nil
}
