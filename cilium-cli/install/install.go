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

package install

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"strings"
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
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
)

var (
	agentMaxUnavailable                = intstr.FromInt(2)
	varTrue                            = true
	hostToContainer                    = corev1.MountPropagationHostToContainer
	agentTerminationGracePeriodSeconds = int64(1)
	hostPathDirectoryOrCreate          = corev1.HostPathDirectoryOrCreate
	hostPathFileOrCreate               = corev1.HostPathFileOrCreate
	secretDefaultMode                  = int32(420)
	operatorReplicas                   = int32(1)
	operatorMaxSurge                   = intstr.FromInt(1)
	operatorMaxUnavailable             = intstr.FromInt(1)
)

const (
	ipamKubernetes  = "kubernetes"
	ipamClusterPool = "cluster-pool"
	ipamENI         = "eni"
	ipamAzure       = "azure"
)

const (
	encryptionDisabled  = "disabled"
	encryptionIPsec     = "ipsec"
	encryptionWireguard = "wireguard"
)

var ciliumClusterRole = &rbacv1.ClusterRole{
	ObjectMeta: metav1.ObjectMeta{
		Name: defaults.AgentClusterRoleName,
	},
	Rules: []rbacv1.PolicyRule{
		{
			APIGroups: []string{"networking.k8s.io"},
			Resources: []string{"networkpolicies"},
			Verbs:     []string{"get", "list", "watch"},
		},
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
			APIGroups: []string{""},
			Resources: []string{"pods", "pods/finalizers"},
			Verbs:     []string{"get", "list", "watch", "update", "delete"},
		},
		{
			APIGroups: []string{""},
			Resources: []string{"nodes"},
			Verbs:     []string{"get", "list", "watch", "update"},
		},
		{
			APIGroups: []string{""},
			Resources: []string{"nodes", "nodes/status"},
			Verbs:     []string{"patch"},
		},
		{
			APIGroups: []string{"apiextensions.k8s.io"},
			Resources: []string{"customresourcedefinitions"},
			Verbs:     []string{"get", "create", "list", "watch", "update"},
		},
		{
			APIGroups: []string{"cilium.io"},
			Resources: []string{
				"ciliumnetworkpolicies",
				"ciliumnetworkpolicies/status",
				"ciliumnetworkpolicies/finalizers",
				"ciliumclusterwidenetworkpolicies",
				"ciliumclusterwidenetworkpolicies/status",
				"ciliumclusterwidenetworkpolicies/finalizers",
				"ciliumendpoints",
				"ciliumendpoints/status",
				"ciliumendpoints/finalizers",
				"ciliumnodes",
				"ciliumnodes/status",
				"ciliumnodes/finalizers",
				"ciliumidentities",
				"ciliumidentities/finalizers",
				"ciliumlocalredirectpolicies",
				"ciliumlocalredirectpolicies/status",
				"ciliumlocalredirectpolicies/finalizers",
			},
			Verbs: []string{"*"},
		},
	},
}

var operatorClusterRole = &rbacv1.ClusterRole{
	ObjectMeta: metav1.ObjectMeta{
		Name: defaults.OperatorClusterRoleName,
	},
	Rules: []rbacv1.PolicyRule{
		// to automatically delete [core|kube]dns pods so that are starting to being
		// managed by Cilium
		{
			APIGroups: []string{""},
			Resources: []string{"pods"},
			Verbs:     []string{"get", "list", "watch", "delete"},
		},
		{
			APIGroups: []string{"discovery.k8s.io"},
			Resources: []string{"endpointslices"},
			Verbs:     []string{"get", "list", "watch"},
		},
		{
			APIGroups: []string{""},
			Resources: []string{
				"services", "endpoints", // to perform the translation of a CNP that contains `ToGroup` to its endpoints
				"namespaces", // to check apiserver connectivity
			},
			Verbs: []string{"get", "list", "watch"},
		},
		{

			APIGroups: []string{""},
			Resources: []string{"services/status"}, // to perform LB IP allocation for BGP
			Verbs:     []string{"update"},
		},
		{
			APIGroups: []string{"cilium.io"},
			Resources: []string{
				"ciliumnetworkpolicies",
				"ciliumnetworkpolicies/status",
				"ciliumnetworkpolicies/finalizers",
				"ciliumclusterwidenetworkpolicies",
				"ciliumclusterwidenetworkpolicies/status",
				"ciliumclusterwidenetworkpolicies/finalizers",
				"ciliumendpoints",
				"ciliumendpoints/status",
				"ciliumendpoints/finalizers",
				"ciliumnodes",
				"ciliumnodes/status",
				"ciliumnodes/finalizers",
				"ciliumidentities",
				"ciliumidentities/status",
				"ciliumidentities/finalizers",
				"ciliumlocalredirectpolicies",
				"ciliumlocalredirectpolicies/status",
				"ciliumlocalredirectpolicies/finalizers",
			},
			Verbs: []string{"*"},
		},
		{
			APIGroups: []string{"apiextensions.k8s.io"},
			Resources: []string{"customresourcedefinitions"},
			Verbs:     []string{"create", "get", "list", "watch", "update"},
		},
		// For cilium-operator running in HA mode.
		//
		// Cilium operator running in HA mode requires the use of
		// ResourceLock for Leader Election between mulitple running
		// instances.  The preferred way of doing this is to use
		// LeasesResourceLock as edits to Leases are less common and
		// fewer objects in the cluster watch "all Leases".  The
		// support for leases was introduced in coordination.k8s.io/v1
		// during Kubernetes 1.14 release.  In Cilium we currently
		// don't support HA mode for K8s version < 1.14. This condition
		// make sure that we only authorize access to leases resources
		// in supported K8s versions.
		{
			APIGroups: []string{"coordination.k8s.io"},
			Resources: []string{"leases"},
			Verbs:     []string{"create", "get", "update"},
		},
	},
}

func (k *K8sInstaller) generateAgentDaemonSet() *appsv1.DaemonSet {
	ds := &appsv1.DaemonSet{
		ObjectMeta: metav1.ObjectMeta{
			Name: defaults.AgentDaemonSetName,
			Labels: map[string]string{
				"k8s-app": "cilium",
			},
		},
		Spec: appsv1.DaemonSetSpec{
			Selector: &metav1.LabelSelector{
				MatchLabels: map[string]string{
					"k8s-app": "cilium",
				},
			},
			UpdateStrategy: appsv1.DaemonSetUpdateStrategy{
				Type: appsv1.RollingUpdateDaemonSetStrategyType,
				RollingUpdate: &appsv1.RollingUpdateDaemonSet{
					MaxUnavailable: &agentMaxUnavailable,
				},
			},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Name: defaults.AgentDaemonSetName,
					Labels: map[string]string{
						"k8s-app": "cilium",
					},
				},
				Spec: corev1.PodSpec{
					Affinity: &corev1.Affinity{
						PodAntiAffinity: &corev1.PodAntiAffinity{
							RequiredDuringSchedulingIgnoredDuringExecution: []corev1.PodAffinityTerm{
								{
									LabelSelector: &metav1.LabelSelector{
										MatchExpressions: []metav1.LabelSelectorRequirement{
											{Key: "k8s-app", Operator: metav1.LabelSelectorOpIn, Values: []string{"cilium"}},
										},
									},
									TopologyKey: "kubernetes.io/hostname",
								},
							},
						},
					},
					HostNetwork:                   true,
					RestartPolicy:                 corev1.RestartPolicyAlways,
					PriorityClassName:             "system-node-critical",
					ServiceAccountName:            defaults.AgentServiceAccountName,
					DeprecatedServiceAccount:      defaults.AgentServiceAccountName, // TODO(tgraf) do we still need this?
					TerminationGracePeriodSeconds: &agentTerminationGracePeriodSeconds,
					Tolerations: []corev1.Toleration{
						{
							Operator: corev1.TolerationOpExists,
						},
					},
					Containers: []corev1.Container{
						{
							Name:            "cilium-agent",
							Command:         []string{"cilium-agent"},
							Args:            []string{"--config-dir=/tmp/cilium/config-map"},
							Image:           k.fqAgentImage(),
							ImagePullPolicy: corev1.PullIfNotPresent,
							LivenessProbe: &corev1.Probe{
								Handler: corev1.Handler{
									HTTPGet: &corev1.HTTPGetAction{
										Host:   "127.0.0.1",
										Path:   "/healthz",
										Port:   intstr.FromInt(9876),
										Scheme: corev1.URISchemeHTTP,
										HTTPHeaders: []corev1.HTTPHeader{
											{
												Name:  "brief",
												Value: "true",
											},
										},
									},
								},
								TimeoutSeconds:      int32(5),
								SuccessThreshold:    int32(1),
								PeriodSeconds:       int32(30),
								InitialDelaySeconds: int32(120),
								FailureThreshold:    int32(10),
							},
							ReadinessProbe: &corev1.Probe{
								Handler: corev1.Handler{
									HTTPGet: &corev1.HTTPGetAction{
										Host:   "127.0.0.1",
										Path:   "/healthz",
										Port:   intstr.FromInt(9876),
										Scheme: corev1.URISchemeHTTP,
										HTTPHeaders: []corev1.HTTPHeader{
											{
												Name:  "brief",
												Value: "true",
											},
										},
									},
								},
								TimeoutSeconds:      int32(5),
								SuccessThreshold:    int32(1),
								PeriodSeconds:       int32(30),
								InitialDelaySeconds: int32(5),
								FailureThreshold:    int32(3),
							},
							Env: []corev1.EnvVar{
								{
									Name: "K8S_NODE_NAME",
									ValueFrom: &corev1.EnvVarSource{
										FieldRef: &corev1.ObjectFieldSelector{
											APIVersion: "v1",
											FieldPath:  "spec.nodeName",
										},
									},
								},
								{
									Name: "CILIUM_K8S_NAMESPACE",
									ValueFrom: &corev1.EnvVarSource{
										FieldRef: &corev1.ObjectFieldSelector{
											APIVersion: "v1",
											FieldPath:  "metadata.namespace",
										},
									},
								},
								{
									Name: "CILIUM_FLANNEL_MASTER_DEVICE",
									ValueFrom: &corev1.EnvVarSource{
										ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
											LocalObjectReference: corev1.LocalObjectReference{
												Name: "cilium-config",
											},
											Key:      "flannel-master-device",
											Optional: &varTrue,
										},
									},
								},
								{
									Name: "CILIUM_FLANNEL_UNINSTALL_ON_EXIT",
									ValueFrom: &corev1.EnvVarSource{
										ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
											LocalObjectReference: corev1.LocalObjectReference{
												Name: "cilium-config",
											},
											Key:      "flannel-uninstall-on-exit",
											Optional: &varTrue,
										},
									},
								},
								{
									Name:  "CILIUM_CLUSTERMESH_CONFIG",
									Value: "/var/lib/cilium/clustermesh/",
								},
								{
									Name: "CILIUM_CNI_CHAINING_MODE",
									ValueFrom: &corev1.EnvVarSource{
										ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
											LocalObjectReference: corev1.LocalObjectReference{
												Name: "cilium-config",
											},
											Key:      "cni-chaining-mode",
											Optional: &varTrue,
										},
									},
								},
								{
									Name: "CILIUM_CUSTOM_CNI_CONF",
									ValueFrom: &corev1.EnvVarSource{
										ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
											LocalObjectReference: corev1.LocalObjectReference{
												Name: "cilium-config",
											},
											Key:      "custom-cni-conf",
											Optional: &varTrue,
										},
									},
								},
							},
							Lifecycle: &corev1.Lifecycle{
								PostStart: &corev1.Handler{
									Exec: &corev1.ExecAction{
										Command: []string{"/cni-install.sh", "--enable-debug=false"},
									},
								},
								PreStop: &corev1.Handler{
									Exec: &corev1.ExecAction{
										Command: []string{"/cni-uninstall.sh"},
									},
								},
							},
							SecurityContext: &corev1.SecurityContext{
								Capabilities: &corev1.Capabilities{
									Add: []corev1.Capability{"NET_ADMIN", "SYS_MODULE"},
								},
								Privileged: &varTrue,
							},
							VolumeMounts: []corev1.VolumeMount{
								{
									Name:      "bpf-maps",
									MountPath: "/sys/fs/bpf",
								},
								{
									Name:      "cilium-run",
									MountPath: "/var/run/cilium",
								},
								{
									Name:      "cni-path",
									MountPath: "/host/opt/cni/bin",
								},
								{
									Name:      "etc-cni-netd",
									MountPath: "/host/etc/cni/net.d",
								},
								{
									Name:      "clustermesh-secrets",
									MountPath: "/var/lib/cilium/clustermesh",
									ReadOnly:  true,
								},
								{
									Name:      "cilium-config-path",
									MountPath: "/tmp/cilium/config-map",
									ReadOnly:  true,
								},
								{
									// Needed to be able to load kernel modules
									Name:      "lib-modules",
									MountPath: "/lib/modules",
									ReadOnly:  true,
								},
								{
									Name:      "xtables-lock",
									MountPath: "/run/xtables.lock",
								},
								{
									Name:      "hubble-tls",
									MountPath: "/var/lib/cilium/tls/hubble",
									ReadOnly:  true,
								},
							},
						},
					},
					InitContainers: []corev1.Container{
						{
							Name:            "clean-cilium-state",
							Command:         []string{"/init-container.sh"},
							Image:           k.fqAgentImage(),
							ImagePullPolicy: corev1.PullIfNotPresent,
							Env: []corev1.EnvVar{
								{
									Name: "CILIUM_ALL_STATE",
									ValueFrom: &corev1.EnvVarSource{
										ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
											LocalObjectReference: corev1.LocalObjectReference{
												Name: "cilium-config",
											},
											Key:      "clean-cilium-state",
											Optional: &varTrue,
										},
									},
								},
								{
									Name: "CILIUM_BPF_STATE",
									ValueFrom: &corev1.EnvVarSource{
										ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
											LocalObjectReference: corev1.LocalObjectReference{
												Name: "cilium-config",
											},
											Key:      "clean-cilium-bpf-state",
											Optional: &varTrue,
										},
									},
								},
								{
									Name: "CILIUM_WAIT_BPF_MOUNT",
									ValueFrom: &corev1.EnvVarSource{
										ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
											LocalObjectReference: corev1.LocalObjectReference{
												Name: "cilium-config",
											},
											Key:      "wait-bpf-mount",
											Optional: &varTrue,
										},
									},
								},
							},
							SecurityContext: &corev1.SecurityContext{
								Capabilities: &corev1.Capabilities{
									Add: []corev1.Capability{"NET_ADMIN"},
								},
								Privileged: &varTrue,
							},
							VolumeMounts: []corev1.VolumeMount{
								{
									Name:             "bpf-maps",
									MountPath:        "/sys/fs/bpf",
									MountPropagation: &hostToContainer,
								},
								{
									Name:      "cilium-run",
									MountPath: "/var/run/cilium",
								},
							},
							Resources: corev1.ResourceRequirements{
								Requests: corev1.ResourceList{
									corev1.ResourceCPU:    resource.MustParse("100m"),
									corev1.ResourceMemory: resource.MustParse("100Mi"),
								},
							},
						},
					},
					Volumes: []corev1.Volume{
						{
							// To keep state between restarts / upgrades
							Name: "cilium-run",
							VolumeSource: corev1.VolumeSource{
								HostPath: &corev1.HostPathVolumeSource{
									Path: k.daemonRunPathOnHost(),
									Type: &hostPathDirectoryOrCreate,
								},
							},
						},
						{
							// To keep state between restarts / upgrades for bpf maps
							Name: "bpf-maps",
							VolumeSource: corev1.VolumeSource{
								HostPath: &corev1.HostPathVolumeSource{
									Path: "/sys/fs/bpf",
									Type: &hostPathDirectoryOrCreate,
								},
							},
						},
						{
							// To install cilium cni plugin in the host
							Name: "cni-path",
							VolumeSource: corev1.VolumeSource{
								HostPath: &corev1.HostPathVolumeSource{
									Path: k.cniBinPathOnHost(),
									Type: &hostPathDirectoryOrCreate,
								},
							},
						},
						{
							// To install cilium cni configuration in the host
							Name: "etc-cni-netd",
							VolumeSource: corev1.VolumeSource{
								HostPath: &corev1.HostPathVolumeSource{
									Path: k.cniConfPathOnHost(),
									Type: &hostPathDirectoryOrCreate,
								},
							},
						},
						{
							// To be able to load kernel modules
							Name: "lib-modules",
							VolumeSource: corev1.VolumeSource{
								HostPath: &corev1.HostPathVolumeSource{
									Path: "/lib/modules",
								},
							},
						},
						{
							// To access iptables concurrently with other processes (e.g. kube-proxy)
							Name: "xtables-lock",
							VolumeSource: corev1.VolumeSource{
								HostPath: &corev1.HostPathVolumeSource{
									Path: "/run/xtables.lock",
									Type: &hostPathFileOrCreate,
								},
							},
						},
						{
							// To read the clustermesh configuration
							Name: "clustermesh-secrets",
							VolumeSource: corev1.VolumeSource{
								Secret: &corev1.SecretVolumeSource{
									SecretName:  "cilium-clustermesh",
									Optional:    &varTrue,
									DefaultMode: &secretDefaultMode,
								},
							},
						},
						{
							// To read the configuration from the config map
							Name: "cilium-config-path",
							VolumeSource: corev1.VolumeSource{
								ConfigMap: &corev1.ConfigMapVolumeSource{
									LocalObjectReference: corev1.LocalObjectReference{
										Name: "cilium-config",
									},
								},
							},
						},
						{
							Name: "hubble-tls",
							VolumeSource: corev1.VolumeSource{
								Projected: &corev1.ProjectedVolumeSource{
									Sources: []corev1.VolumeProjection{
										{
											Secret: &corev1.SecretProjection{
												LocalObjectReference: corev1.LocalObjectReference{
													Name: defaults.HubbleServerSecretName,
												},
												Items: []corev1.KeyToPath{
													{
														Key:  corev1.TLSCertKey,
														Path: "server.crt",
													},
													{
														Key:  corev1.TLSPrivateKeyKey,
														Path: "server.key",
													},
													{
														Key:  defaults.CASecretCertName,
														Path: "client-ca.crt",
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
		},
	}

	nodeInitContainers := []corev1.Container{}
	auxVolumes := []corev1.Volume{}
	auxVolumeMounts := []corev1.VolumeMount{}

	if k.params.Encryption == encryptionIPsec {
		auxVolumes = append(auxVolumes, corev1.Volume{
			Name: "cilium-ipsec-secrets",
			VolumeSource: corev1.VolumeSource{
				Secret: &corev1.SecretVolumeSource{
					SecretName: defaults.EncryptionSecretName,
				},
			},
		})

		auxVolumeMounts = append(auxVolumeMounts, corev1.VolumeMount{
			Name:      "cilium-ipsec-secrets",
			MountPath: "/etc/ipsec",
		})
	}

	switch k.flavor.Kind {
	case k8s.KindGKE:
		nodeInitContainers = append(nodeInitContainers, corev1.Container{
			Name:            "wait-for-node-init",
			Image:           k.fqAgentImage(),
			ImagePullPolicy: corev1.PullIfNotPresent,
			Command:         []string{"sh", "-c", `until stat /tmp/cilium-bootstrap/time > /dev/null 2>&1; do echo "Waiting for GKE node-init to run..."; sleep 1; done`},
			VolumeMounts: []corev1.VolumeMount{
				{
					Name:      "cilium-bootstrap",
					MountPath: "/tmp/cilium-bootstrap",
				},
			},
		})

		auxVolumes = append(auxVolumes, corev1.Volume{
			Name: "cilium-bootstrap",
			VolumeSource: corev1.VolumeSource{
				HostPath: &corev1.HostPathVolumeSource{
					Path: "/tmp/cilium-bootstrap",
					Type: &hostPathDirectoryOrCreate,
				},
			},
		})

	}

	mountCmd := `mount | grep "/sys/fs/bpf type bpf" || { echo "Mounting eBPF filesystem..."; mount bpffs /sys/fs/bpf -t bpf; }`
	nodeInitContainers = append(nodeInitContainers, corev1.Container{
		Name:            "ebpf-mount",
		Image:           k.fqAgentImage(),
		ImagePullPolicy: corev1.PullIfNotPresent,
		Command:         []string{"nsenter", "--mount=/hostproc/1/ns/mnt", "--", "sh", "-c", mountCmd},
		SecurityContext: &corev1.SecurityContext{
			Privileged: &varTrue,
			// This doesn't work yet for some reason. It would allow to drop privileged mode:w
			//
			// Capabilities: &corev1.Capabilities{
			// Add: []corev1.Capability{"SYS_PTRACE", "SYS_ADMIN", "SYS_CHROOT"},
			// },
		},
		VolumeMounts: []corev1.VolumeMount{
			{
				Name:      "host-proc",
				MountPath: "/hostproc",
			},
		},
		Resources: corev1.ResourceRequirements{
			Requests: corev1.ResourceList{
				corev1.ResourceCPU:    resource.MustParse("100m"),
				corev1.ResourceMemory: resource.MustParse("100Mi"),
			},
		},
	})

	auxVolumes = append(auxVolumes, corev1.Volume{
		Name: "host-proc",
		VolumeSource: corev1.VolumeSource{
			HostPath: &corev1.HostPathVolumeSource{
				Path: "/proc",
				Type: &hostPathDirectoryOrCreate,
			},
		},
	})

	ds.Spec.Template.Spec.InitContainers = append(nodeInitContainers, ds.Spec.Template.Spec.InitContainers...)
	ds.Spec.Template.Spec.Volumes = append(ds.Spec.Template.Spec.Volumes, auxVolumes...)
	ds.Spec.Template.Spec.Containers[0].VolumeMounts = append(ds.Spec.Template.Spec.Containers[0].VolumeMounts, auxVolumeMounts...)

	if k.bgpEnabled() {
		ds.Spec.Template.Spec.Containers[0].VolumeMounts = append(ds.Spec.Template.Spec.Containers[0].VolumeMounts,
			corev1.VolumeMount{
				Name:      "bgp-config-path",
				ReadOnly:  true,
				MountPath: "/var/lib/cilium/bgp",
			},
		)
		ds.Spec.Template.Spec.Volumes = append(ds.Spec.Template.Spec.Volumes, corev1.Volume{
			Name: "bgp-config-path",
			VolumeSource: corev1.VolumeSource{
				ConfigMap: &corev1.ConfigMapVolumeSource{
					LocalObjectReference: corev1.LocalObjectReference{
						Name: "bgp-config",
					},
				},
			},
		})
	}

	return ds
}

func (k *K8sInstaller) generateOperatorDeployment() *appsv1.Deployment {
	deployment := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:   defaults.OperatorDeploymentName,
			Labels: defaults.OperatorLabels,
		},
		Spec: appsv1.DeploymentSpec{
			Replicas: &operatorReplicas,
			Selector: &metav1.LabelSelector{
				MatchLabels: defaults.OperatorLabels,
			},
			Strategy: appsv1.DeploymentStrategy{
				Type: appsv1.RollingUpdateDeploymentStrategyType,
				RollingUpdate: &appsv1.RollingUpdateDeployment{
					MaxUnavailable: &operatorMaxUnavailable,
					MaxSurge:       &operatorMaxSurge,
				},
			},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Name:   "cilium-operator",
					Labels: defaults.OperatorLabels,
				},
				Spec: corev1.PodSpec{
					RestartPolicy:                 corev1.RestartPolicyAlways,
					PriorityClassName:             "system-cluster-critical",
					ServiceAccountName:            defaults.OperatorServiceAccountName,
					DeprecatedServiceAccount:      defaults.OperatorServiceAccountName, // TODO(tgraf) do we still need this?
					TerminationGracePeriodSeconds: &agentTerminationGracePeriodSeconds,
					HostNetwork:                   true,
					Tolerations: []corev1.Toleration{
						{
							Operator: corev1.TolerationOpExists,
						},
					},
					Affinity: &corev1.Affinity{
						PodAffinity: &corev1.PodAffinity{
							RequiredDuringSchedulingIgnoredDuringExecution: []corev1.PodAffinityTerm{
								{
									LabelSelector: &metav1.LabelSelector{
										MatchExpressions: []metav1.LabelSelectorRequirement{
											{Key: "io.cilium/app", Operator: metav1.LabelSelectorOpIn, Values: []string{"operator"}},
										},
									},
									TopologyKey: "kubernetes.io/hostname",
								},
							},
						},
					},
					Containers: []corev1.Container{
						{
							Name:            "cilium-operator",
							Command:         k.operatorCommand(),
							Args:            []string{"--config-dir=/tmp/cilium/config-map"},
							Image:           k.fqOperatorImage(),
							ImagePullPolicy: corev1.PullIfNotPresent,
							Env: []corev1.EnvVar{
								{
									Name: "K8S_NODE_NAME",
									ValueFrom: &corev1.EnvVarSource{
										FieldRef: &corev1.ObjectFieldSelector{
											APIVersion: "v1",
											FieldPath:  "spec.nodeName",
										},
									},
								},
								{
									Name: "CILIUM_K8S_NAMESPACE",
									ValueFrom: &corev1.EnvVarSource{
										FieldRef: &corev1.ObjectFieldSelector{
											APIVersion: "v1",
											FieldPath:  "metadata.namespace",
										},
									},
								},
								{
									Name: "CILIUM_DEBUG",
									ValueFrom: &corev1.EnvVarSource{
										ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
											LocalObjectReference: corev1.LocalObjectReference{
												Name: "cilium-config",
											},
											Key:      "debug",
											Optional: &varTrue,
										},
									},
								},
							},
							VolumeMounts: []corev1.VolumeMount{
								{
									Name:      "cilium-config-path",
									MountPath: "/tmp/cilium/config-map",
									ReadOnly:  true,
								},
							},
						},
					},
					Volumes: []corev1.Volume{
						{
							// To read the configuration from the config map
							Name: "cilium-config-path",
							VolumeSource: corev1.VolumeSource{
								ConfigMap: &corev1.ConfigMapVolumeSource{
									LocalObjectReference: corev1.LocalObjectReference{
										Name: "cilium-config",
									},
								},
							},
						},
					},
				},
			},
		},
	}

	switch k.params.DatapathMode {
	case DatapathAwsENI:
		c := &deployment.Spec.Template.Spec.Containers[0]
		c.Env = append(c.Env, corev1.EnvVar{
			Name: "AWS_ACCESS_KEY_ID",
			ValueFrom: &corev1.EnvVarSource{
				SecretKeyRef: &corev1.SecretKeySelector{
					LocalObjectReference: corev1.LocalObjectReference{
						Name: "cilium-aws",
					},
					Key:      "AWS_ACCESS_KEY_ID",
					Optional: &varTrue,
				},
			},
		})

		c.Env = append(c.Env, corev1.EnvVar{
			Name: "AWS_SECRET_ACCESS_KEY",
			ValueFrom: &corev1.EnvVarSource{
				SecretKeyRef: &corev1.SecretKeySelector{
					LocalObjectReference: corev1.LocalObjectReference{
						Name: "cilium-aws",
					},
					Key:      "AWS_SECRET_ACCESS_KEY",
					Optional: &varTrue,
				},
			},
		})

		c.Env = append(c.Env, corev1.EnvVar{
			Name: "AWS_DEFAULT_REGION",
			ValueFrom: &corev1.EnvVarSource{
				SecretKeyRef: &corev1.SecretKeySelector{
					LocalObjectReference: corev1.LocalObjectReference{
						Name: "cilium-aws",
					},
					Key:      "AWS_DEFAULT_REGION",
					Optional: &varTrue,
				},
			},
		})

	case DatapathAzure:
		c := &deployment.Spec.Template.Spec.Containers[0]
		c.Env = append(c.Env, corev1.EnvVar{
			Name:  "AZURE_SUBSCRIPTION_ID",
			Value: k.params.Azure.DerivedSubscriptionID,
		})

		c.Env = append(c.Env, corev1.EnvVar{
			Name:  "AZURE_TENANT_ID",
			Value: k.params.Azure.TenantID,
		})

		c.Env = append(c.Env, corev1.EnvVar{
			Name:  "AZURE_RESOURCE_GROUP",
			Value: k.params.Azure.ResourceGroup,
		})

		c.Env = append(c.Env, corev1.EnvVar{
			Name:  "AZURE_CLIENT_ID",
			Value: k.params.Azure.ClientID,
		})

		c.Env = append(c.Env, corev1.EnvVar{
			Name:  "AZURE_CLIENT_SECRET",
			Value: k.params.Azure.ClientSecret,
		})
	}

	if k.bgpEnabled() {
		deployment.Spec.Template.Spec.Containers[0].VolumeMounts = append(deployment.Spec.Template.Spec.Containers[0].VolumeMounts,
			corev1.VolumeMount{
				Name:      "bgp-config-path",
				ReadOnly:  true,
				MountPath: "/var/lib/cilium/bgp",
			},
		)
		deployment.Spec.Template.Spec.Volumes = append(deployment.Spec.Template.Spec.Volumes, corev1.Volume{
			Name: "bgp-config-path",
			VolumeSource: corev1.VolumeSource{
				ConfigMap: &corev1.ConfigMapVolumeSource{
					LocalObjectReference: corev1.LocalObjectReference{
						Name: "bgp-config",
					},
				},
			},
		})
	}

	return deployment
}

type k8sInstallerImplementation interface {
	ClusterName() string
	ListNodes(ctx context.Context, options metav1.ListOptions) (*corev1.NodeList, error)
	GetCiliumExternalWorkload(ctx context.Context, name string, opts metav1.GetOptions) (*ciliumv2.CiliumExternalWorkload, error)
	CreateCiliumExternalWorkload(ctx context.Context, cew *ciliumv2.CiliumExternalWorkload, opts metav1.CreateOptions) (*ciliumv2.CiliumExternalWorkload, error)
	DeleteCiliumExternalWorkload(ctx context.Context, name string, opts metav1.DeleteOptions) error
	ListCiliumExternalWorkloads(ctx context.Context, opts metav1.ListOptions) (*ciliumv2.CiliumExternalWorkloadList, error)
	CreateServiceAccount(ctx context.Context, namespace string, account *corev1.ServiceAccount, opts metav1.CreateOptions) (*corev1.ServiceAccount, error)
	DeleteServiceAccount(ctx context.Context, namespace, name string, opts metav1.DeleteOptions) error
	GetConfigMap(ctx context.Context, namespace, name string, opts metav1.GetOptions) (*corev1.ConfigMap, error)
	CreateConfigMap(ctx context.Context, namespace string, config *corev1.ConfigMap, opts metav1.CreateOptions) (*corev1.ConfigMap, error)
	DeleteConfigMap(ctx context.Context, namespace, name string, opts metav1.DeleteOptions) error
	CreateClusterRole(ctx context.Context, config *rbacv1.ClusterRole, opts metav1.CreateOptions) (*rbacv1.ClusterRole, error)
	DeleteClusterRole(ctx context.Context, name string, opts metav1.DeleteOptions) error
	CreateClusterRoleBinding(ctx context.Context, role *rbacv1.ClusterRoleBinding, opts metav1.CreateOptions) (*rbacv1.ClusterRoleBinding, error)
	DeleteClusterRoleBinding(ctx context.Context, name string, opts metav1.DeleteOptions) error
	CreateDaemonSet(ctx context.Context, namespace string, ds *appsv1.DaemonSet, opts metav1.CreateOptions) (*appsv1.DaemonSet, error)
	GetDaemonSet(ctx context.Context, namespace, name string, opts metav1.GetOptions) (*appsv1.DaemonSet, error)
	DeleteDaemonSet(ctx context.Context, namespace, name string, opts metav1.DeleteOptions) error
	PatchDaemonSet(ctx context.Context, namespace, name string, pt types.PatchType, data []byte, opts metav1.PatchOptions) (*appsv1.DaemonSet, error)
	GetService(ctx context.Context, namespace, name string, opts metav1.GetOptions) (*corev1.Service, error)
	CreateService(ctx context.Context, namespace string, service *corev1.Service, opts metav1.CreateOptions) (*corev1.Service, error)
	DeleteService(ctx context.Context, namespace, name string, opts metav1.DeleteOptions) error
	DeleteDeployment(ctx context.Context, namespace, name string, opts metav1.DeleteOptions) error
	CreateDeployment(ctx context.Context, namespace string, deployment *appsv1.Deployment, opts metav1.CreateOptions) (*appsv1.Deployment, error)
	GetDeployment(ctx context.Context, namespace, name string, opts metav1.GetOptions) (*appsv1.Deployment, error)
	PatchDeployment(ctx context.Context, namespace, name string, pt types.PatchType, data []byte, opts metav1.PatchOptions) (*appsv1.Deployment, error)
	DeploymentIsReady(ctx context.Context, namespace, deployment string) error
	DeleteNamespace(ctx context.Context, namespace string, opts metav1.DeleteOptions) error
	CreateNamespace(ctx context.Context, namespace string, opts metav1.CreateOptions) (*corev1.Namespace, error)
	GetNamespace(ctx context.Context, namespace string, options metav1.GetOptions) (*corev1.Namespace, error)
	ListPods(ctx context.Context, namespace string, options metav1.ListOptions) (*corev1.PodList, error)
	DeletePod(ctx context.Context, namespace, name string, options metav1.DeleteOptions) error
	ExecInPod(ctx context.Context, namespace, pod, container string, command []string) (bytes.Buffer, error)
	CreateSecret(ctx context.Context, namespace string, secret *corev1.Secret, opts metav1.CreateOptions) (*corev1.Secret, error)
	DeleteSecret(ctx context.Context, namespace, name string, opts metav1.DeleteOptions) error
	GetSecret(ctx context.Context, namespace, name string, opts metav1.GetOptions) (*corev1.Secret, error)
	PatchSecret(ctx context.Context, namespace, name string, pt types.PatchType, data []byte, opts metav1.PatchOptions) (*corev1.Secret, error)
	CreateResourceQuota(ctx context.Context, namespace string, r *corev1.ResourceQuota, opts metav1.CreateOptions) (*corev1.ResourceQuota, error)
	DeleteResourceQuota(ctx context.Context, namespace, name string, opts metav1.DeleteOptions) error
	AutodetectFlavor(ctx context.Context) (k8s.Flavor, error)
	ContextName() (name string)
	CiliumStatus(ctx context.Context, namespace, pod string) (*models.StatusResponse, error)
	ListCiliumEndpoints(ctx context.Context, namespace string, opts metav1.ListOptions) (*ciliumv2.CiliumEndpointList, error)
}

type K8sInstaller struct {
	client      k8sInstallerImplementation
	params      InstallParameters
	flavor      k8s.Flavor
	certManager *certs.CertManager
}

const (
	DatapathTunnel = "tunnel"
	DatapathAwsENI = "aws-eni"
	DatapathGKE    = "gke"
	DatapathAzure  = "azure"

	Microk8sSnapPath = "/var/snap/microk8s/current"
)

type AzureParameters struct {
	ResourceGroupName     string
	SubscriptionID        string
	DerivedSubscriptionID string
	TenantID              string
	ResourceGroup         string
	ClientID              string
	ClientSecret          string
}

type InstallParameters struct {
	Namespace            string
	Writer               io.Writer
	ClusterName          string
	DisableChecks        []string
	Version              string
	AgentImage           string
	OperatorImage        string
	InheritCA            string
	Wait                 bool
	WaitDuration         time.Duration
	DatapathMode         string
	TunnelType           string
	NativeRoutingCIDR    string
	ClusterID            int
	IPAM                 string
	KubeProxyReplacement string
	Azure                AzureParameters
	RestartUnmanagedPods bool
	Encryption           string
	NodeEncryption       bool
	ConfigOverwrites     []string
	configOverwrites     map[string]string
}

func (p *InstallParameters) validate() error {
	p.configOverwrites = map[string]string{}
	for _, config := range p.ConfigOverwrites {
		t := strings.SplitN(config, "=", 2)
		if len(t) != 2 {
			return fmt.Errorf("invalid config overwrite %q, must be in the form key=valye", config)
		}

		p.configOverwrites[t[0]] = t[1]
	}

	return nil
}

func (k *K8sInstaller) cniBinPathOnHost() string {
	switch k.flavor.Kind {
	case k8s.KindGKE:
		return "/home/kubernetes/bin"
	case k8s.KindMicrok8s:
		return Microk8sSnapPath + "/opt/cni/bin"
	}

	return "/opt/cni/bin"
}

func (k *K8sInstaller) cniConfPathOnHost() string {
	switch k.flavor.Kind {
	case k8s.KindMicrok8s:
		return Microk8sSnapPath + "/args/cni-network"
	}

	return "/etc/cni/net.d"
}

func (k *K8sInstaller) daemonRunPathOnHost() string {
	switch k.flavor.Kind {
	case k8s.KindMicrok8s:
		return Microk8sSnapPath + "/var/run/cilium"
	}

	return "/var/run/cilium"
}

func (k *K8sInstaller) fqAgentImage() string {
	return utils.BuildImagePath(k.params.AgentImage, defaults.AgentImage, k.params.Version, defaults.Version)
}

func (k *K8sInstaller) fqOperatorImage() string {
	defaultImage := defaults.OperatorImage
	switch k.params.DatapathMode {
	case DatapathAwsENI:
		defaultImage = defaults.OperatorImageAWS
	case DatapathAzure:
		defaultImage = defaults.OperatorImageAzure
	}

	return utils.BuildImagePath(k.params.OperatorImage, defaultImage, k.params.Version, defaults.Version)
}

func (k *K8sInstaller) operatorCommand() []string {
	switch k.params.DatapathMode {
	case DatapathAwsENI:
		return []string{"cilium-operator-aws"}
	case DatapathAzure:
		return []string{"cilium-operator-azure"}
	}

	return []string{"cilium-operator-generic"}
}

func NewK8sInstaller(client k8sInstallerImplementation, p InstallParameters) (*K8sInstaller, error) {
	if err := (&p).validate(); err != nil {
		return nil, fmt.Errorf("invalid parameters: %w", err)
	}

	cm := certs.NewCertManager(client, certs.Parameters{Namespace: p.Namespace})

	return &K8sInstaller{
		client:      client,
		params:      p,
		certManager: cm,
	}, nil
}

func (k *K8sInstaller) Log(format string, a ...interface{}) {
	fmt.Fprintf(k.params.Writer, format+"\n", a...)
}

func (k *K8sInstaller) generateConfigMap() (*corev1.ConfigMap, error) {
	m := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name: defaults.ConfigMapName,
		},
		Data: map[string]string{
			// Identity allocation mode selects how identities are shared between cilium
			// nodes by setting how they are stored. The options are "crd" or "kvstore".
			// - "crd" stores identities in kubernetes as CRDs (custom resource definition).
			//   These can be queried with:
			//     kubectl get ciliumid
			// - "kvstore" stores identities in a kvstore, etcd or consul, that is
			//   configured below. Cilium versions before 1.6 supported only the kvstore
			//   backend. Upgrades from these older cilium versions should continue using
			//   the kvstore by commenting out the identity-allocation-mode below, or
			//   setting it to "kvstore".
			"identity-allocation-mode":    "crd",
			"cilium-endpoint-gc-interval": "5m0s",

			// If you want to run cilium in debug mode change this value to true
			"debug": "false",
			// The agent can be put into the following three policy enforcement modes
			// default, always and never.
			// https://docs.cilium.io/en/latest/policy/intro/#policy-enforcement-modes
			"enable-policy": "default",

			// Enable IPv4 addressing. If enabled, all endpoints are allocated an IPv4
			// address.
			"enable-ipv4": "true",

			// Enable IPv6 addressing. If enabled, all endpoints are allocated an IPv6
			// address.
			"enable-ipv6": "false",
			// Users who wish to specify their own custom CNI configuration file must set
			// custom-cni-conf to "true", otherwise Cilium may overwrite the configuration.
			"custom-cni-conf":        "false",
			"enable-bpf-clock-probe": "true",
			// If you want cilium monitor to aggregate tracing for packets, set this level
			// to "low", "medium", or "maximum". The higher the level, the less packets
			// that will be seen in monitor output.
			"monitor-aggregation": "medium",

			// The monitor aggregation interval governs the typical time between monitor
			// notification events for each allowed connection.
			//
			// Only effective when monitor aggregation is set to "medium" or higher.
			"monitor-aggregation-interval": "5s",

			// The monitor aggregation flags determine which TCP flags which, upon the
			// first observation, cause monitor notifications to be generated.
			//
			// Only effective when monitor aggregation is set to "medium" or higher.
			"monitor-aggregation-flags": "all",
			// Specifies the ratio (0.0-1.0) of total system memory to use for dynamic
			// sizing of the TCP CT, non-TCP CT, NAT and policy BPF maps.
			"bpf-map-dynamic-size-ratio": "0.0025",
			// bpf-policy-map-max specifies the maximum number of entries in endpoint
			// policy map (per endpoint)
			"bpf-policy-map-max": "16384",
			// bpf-lb-map-max specifies the maximum number of entries in bpf lb service,
			// backend and affinity maps.
			"bpf-lb-map-max": "65536",
			// Pre-allocation of map entries allows per-packet latency to be reduced, at
			// the expense of up-front memory allocation for the entries in the maps. The
			// default value below will minimize memory usage in the default installation;
			// users who are sensitive to latency may consider setting this to "true".
			//
			// This option was introduced in Cilium 1.4. Cilium 1.3 and earlier ignore
			// this option and behave as though it is set to "true".
			//
			// If this value is modified, then during the next Cilium startup the restore
			// of existing endpoints and tracking of ongoing connections may be disrupted.
			// As a result, reply packets may be dropped and the load-balancing decisions
			// for established connections may change.
			//
			// If this option is set to "false" during an upgrade from 1.3 or earlier to
			// 1.4 or later, then it may cause one-time disruptions during the upgrade.
			"preallocate-bpf-maps": "false",

			// Regular expression matching compatible Istio sidecar istio-proxy
			// container image names
			"sidecar-istio-proxy-image": "cilium/istio_proxy",

			// Name of the cluster. Only relevant when building a mesh of clusters.
			"cluster-name": k.params.ClusterName,
			// Unique ID of the cluster. Must be unique across all conneted clusters and
			// in the range of 1 and 255. Only relevant when building a mesh of clusters.
			"cluster-id": "",

			// Enables L7 proxy for L7 policy enforcement and visibility
			"enable-l7-proxy": "true",

			// wait-bpf-mount makes init container wait until bpf filesystem is mounted
			"wait-bpf-mount": "true",

			"masquerade":            "true",
			"enable-bpf-masquerade": "true",

			"enable-xt-socket-fallback":           "true",
			"install-iptables-rules":              "true",
			"install-no-conntrack-iptables-rules": "false",

			"auto-direct-node-routes":             "false",
			"enable-bandwidth-manager":            "true",
			"enable-local-redirect-policy":        "false",
			"enable-health-check-nodeport":        "true",
			"node-port-bind-protection":           "true",
			"enable-auto-protect-node-port-range": "true",
			"enable-session-affinity":             "true",
			"enable-endpoint-health-checking":     "true",
			"enable-health-checking":              "true",
			"enable-well-known-identities":        "false",
			"enable-remote-node-identity":         "true",
			"operator-api-serve-addr":             "127.0.0.1:9234",
			"disable-cnp-status-updates":          "true",
		},
	}

	if k.params.ClusterID != 0 {
		m.Data["cluster-id"] = fmt.Sprintf("%d", k.params.ClusterID)
	}

	if k.params.NativeRoutingCIDR != "" {
		m.Data["native-routing-cidr"] = k.params.NativeRoutingCIDR
	}

	m.Data["kube-proxy-replacement"] = k.params.KubeProxyReplacement

	m.Data["ipam"] = k.params.IPAM
	switch k.params.IPAM {
	case ipamClusterPool:
		m.Data["cluster-pool-ipv4-cidr"] = "10.0.0.0/8"
		m.Data["cluster-pool-ipv4-mask-size"] = "24"
	}

	switch k.params.DatapathMode {
	case DatapathTunnel:
		t := k.params.TunnelType
		if t == "" {
			t = defaults.TunnelType
		}
		m.Data["tunnel"] = t

	case DatapathAwsENI:
		m.Data["tunnel"] = "disabled"
		m.Data["enable-endpoint-routes"] = "true"
		m.Data["auto-create-cilium-node-resource"] = "true"
		// TODO(tgraf) Is this really sane?
		m.Data["egress-masquerade-interfaces"] = "eth0"

	case DatapathGKE:
		m.Data["tunnel"] = "disabled"
		m.Data["enable-endpoint-routes"] = "true"
		m.Data["enable-local-node-route"] = "false"

	case DatapathAzure:
		m.Data["tunnel"] = "disabled"
		m.Data["enable-endpoint-routes"] = "true"
		m.Data["auto-create-cilium-node-resource"] = "true"
		m.Data["enable-local-node-route"] = "false"
		m.Data["masquerade"] = "false"
		m.Data["enable-bpf-masquerade"] = "false"
	}

	switch k.flavor.Kind {
	case k8s.KindGKE:
		m.Data["gke-node-init-script"] = nodeInitStartupScriptGKE
	}

	switch k.params.Encryption {
	case encryptionIPsec:
		m.Data["enable-ipsec"] = "true"
		m.Data["ipsec-key-file"] = "/etc/ipsec/keys"

		if k.params.NodeEncryption {
			m.Data["encrypt-node"] = "true"
		}
	case encryptionWireguard:
		m.Data["enable-wireguard"] = "true"
		// TODO(gandro): Future versions of Cilium will remove the following
		// two limitations, we will need to have set the config map values
		// based on the installed Cilium version
		m.Data["enable-l7-proxy"] = "false"
		k.Log("ℹ️  L7 proxy disabled due to Wireguard encryption")

		if k.params.NodeEncryption {
			k.Log("⚠️️  Wireguard does not support node encryption yet")
		}
	}

	for key, value := range k.params.configOverwrites {
		k.Log("ℹ️  Manual overwrite in ConfigMap: %s=%s", key, value)
		m.Data[key] = value
	}

	if m.Data["install-no-conntrack-iptables-rules"] == "true" {
		switch k.params.DatapathMode {
		case DatapathAwsENI:
			return nil, fmt.Errorf("--install-no-conntrack-iptables-rules cannot be enabled on AWS EKS")
		case DatapathGKE:
			return nil, fmt.Errorf("--install-no-conntrack-iptables-rules cannot be enabled on Google GKE")
		case DatapathAzure:
			return nil, fmt.Errorf("--install-no-conntrack-iptables-rules cannot be enabled on Azure AKS")
		}

		if m.Data["tunnel"] != "disabled" {
			return nil, fmt.Errorf("--install-no-conntrack-iptables-rules requires tunneling to be disabled")
		}

		if m.Data["kube-proxy-replacement"] != "strict" {
			return nil, fmt.Errorf("--install-no-conntrack-iptables-rules requires kube-proxy replacement to be enabled")
		}

		if m.Data["cni-chaining-mode"] != "" {
			return nil, fmt.Errorf("--install-no-conntrack-iptables-rules cannot be enabled with CNI chaining")
		}
	}

	return m, nil
}

func (k *K8sInstaller) deployResourceQuotas(ctx context.Context) error {
	k.Log("🚀 Creating Resource quotas...")

	ciliumResourceQuota := &corev1.ResourceQuota{
		ObjectMeta: metav1.ObjectMeta{
			Name: defaults.AgentResourceQuota,
		},
		Spec: corev1.ResourceQuotaSpec{
			Hard: corev1.ResourceList{
				// 5k nodes * 2 DaemonSets (Cilium and cilium node init)
				corev1.ResourcePods: resource.MustParse("10k"),
			},
			ScopeSelector: &corev1.ScopeSelector{
				MatchExpressions: []corev1.ScopedResourceSelectorRequirement{
					{
						ScopeName: corev1.ResourceQuotaScopePriorityClass,
						Operator:  corev1.ScopeSelectorOpIn,
						Values:    []string{"system-node-critical"},
					},
				},
			},
		},
	}

	if _, err := k.client.CreateResourceQuota(ctx, k.params.Namespace, ciliumResourceQuota, metav1.CreateOptions{}); err != nil {
		return err
	}

	operatorResourceQuota := &corev1.ResourceQuota{
		ObjectMeta: metav1.ObjectMeta{
			Name: defaults.OperatorResourceQuota,
		},
		Spec: corev1.ResourceQuotaSpec{
			Hard: corev1.ResourceList{
				// 15 "clusterwide" Cilium Operator pods for HA
				corev1.ResourcePods: resource.MustParse("15"),
			},
			ScopeSelector: &corev1.ScopeSelector{
				MatchExpressions: []corev1.ScopedResourceSelectorRequirement{
					{
						ScopeName: corev1.ResourceQuotaScopePriorityClass,
						Operator:  corev1.ScopeSelectorOpIn,
						Values:    []string{"system-cluster-critical"},
					},
				},
			},
		},
	}

	if _, err := k.client.CreateResourceQuota(ctx, k.params.Namespace, operatorResourceQuota, metav1.CreateOptions{}); err != nil {
		return err
	}

	return nil
}

func (k *K8sInstaller) restartUnmanagedPods(ctx context.Context) error {
	var printed bool

	pods, err := k.client.ListPods(ctx, "", metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("unable to list pods: %w", err)
	}

	// If not pods are running, skip. This avoids attemptingm to retrieve
	// CiliumEndpoints if no pods are present at all. Cilium will not be
	// running either.
	if len(pods.Items) == 0 {
		return nil
	}

	cepMap := map[string]struct{}{}
	ceps, err := k.client.ListCiliumEndpoints(ctx, "", metav1.ListOptions{})
	if err != nil {
		// When the CEP has not been registered yet, it's impossible
		// for any pods to be managed by Cilium.
		if err.Error() != "the server could not find the requested resource (get ciliumendpoints.cilium.io)" {
			return fmt.Errorf("unable to list cilium endpoints: %w", err)
		}
	} else {
		for _, cep := range ceps.Items {
			cepMap[cep.Namespace+"/"+cep.Name] = struct{}{}
		}
	}

	for _, pod := range pods.Items {
		if !pod.Spec.HostNetwork {
			if _, ok := cepMap[pod.Namespace+"/"+pod.Name]; ok {
				continue
			}

			if !printed {
				k.Log("♻️  Restarting unmanaged pods...")
				printed = true
			}
			err := k.client.DeletePod(ctx, pod.Namespace, pod.Name, metav1.DeleteOptions{})
			if err != nil {
				k.Log("⚠️  Unable to restart pod %s/%s: %s", pod.Namespace, pod.Name, err)
			} else {
				k.Log("♻️  Restarted unmanaged pod %s/%s", pod.Namespace, pod.Name)
			}
		}
	}

	return nil

}

func (k *K8sInstaller) Install(ctx context.Context) error {
	if err := k.autodetectAndValidate(ctx); err != nil {
		return err
	}

	switch k.flavor.Kind {
	case k8s.KindEKS:
		if _, err := k.client.GetDaemonSet(ctx, "kube-system", "aws-node", metav1.GetOptions{}); err == nil {
			k.Log("🔥 Deleting aws-node DaemonSet...")
			if err := k.client.DeleteDaemonSet(ctx, "kube-system", "aws-node", metav1.DeleteOptions{}); err != nil {
				return err
			}
		}
	case k8s.KindGKE:
		if k.params.NativeRoutingCIDR == "" {
			cidr, err := k.gkeNativeRoutingCIDR(ctx, k.client.ContextName())
			if err != nil {
				k.Log("❌ Unable to auto-detect GKE native routing CIDR. Is \"gcloud\" installed?")
				k.Log("ℹ️  You can set the native routing CIDR manually with --native-routing-cidr")
				return err
			}
			k.params.NativeRoutingCIDR = cidr
		}

		if err := k.deployResourceQuotas(ctx); err != nil {
			return err
		}

	case k8s.KindAKS:
		if k.params.Azure.ResourceGroupName == "" {
			k.Log("❌ Azure resoure group is required, please specify --azure-resource-group")
			return fmt.Errorf("missing Azure resource group name")
		}

		if err := k.createAzureServicePrincipal(ctx); err != nil {
			return err
		}
	}

	if err := k.installCerts(ctx); err != nil {
		return err
	}

	k.Log("🚀 Creating Service accounts...")
	if _, err := k.client.CreateServiceAccount(ctx, k.params.Namespace, k8s.NewServiceAccount(defaults.AgentServiceAccountName), metav1.CreateOptions{}); err != nil {
		return err
	}

	if _, err := k.client.CreateServiceAccount(ctx, k.params.Namespace, k8s.NewServiceAccount(defaults.OperatorServiceAccountName), metav1.CreateOptions{}); err != nil {
		return err
	}

	k.Log("🚀 Creating Cluster roles...")
	if _, err := k.client.CreateClusterRole(ctx, ciliumClusterRole, metav1.CreateOptions{}); err != nil {
		return err
	}

	if _, err := k.client.CreateClusterRoleBinding(ctx, k8s.NewClusterRoleBinding(defaults.AgentClusterRoleName, k.params.Namespace, defaults.AgentServiceAccountName), metav1.CreateOptions{}); err != nil {
		return err
	}

	if _, err := k.client.CreateClusterRole(ctx, operatorClusterRole, metav1.CreateOptions{}); err != nil {
		return err
	}

	if _, err := k.client.CreateClusterRoleBinding(ctx, k8s.NewClusterRoleBinding(defaults.OperatorClusterRoleName, k.params.Namespace, defaults.OperatorServiceAccountName), metav1.CreateOptions{}); err != nil {
		return err
	}

	if k.params.Encryption == encryptionIPsec {
		if err := k.createEncryptionSecret(ctx); err != nil {
			return err
		}
	}

	k.Log("🚀 Creating ConfigMap...")
	configMap, err := k.generateConfigMap()
	if err != nil {
		return fmt.Errorf("cannot generate ConfigMap: %w", err)
	}

	if _, err := k.client.CreateConfigMap(ctx, k.params.Namespace, configMap, metav1.CreateOptions{}); err != nil {
		return err
	}

	switch k.flavor.Kind {
	case k8s.KindGKE:
		k.Log("🚀 Creating GKE Node Init DaemonSet...")
		if _, err := k.client.CreateDaemonSet(ctx, k.params.Namespace, k.generateGKEInitDaemonSet(), metav1.CreateOptions{}); err != nil {
			return err
		}
	}

	k.Log("🚀 Creating Agent DaemonSet...")
	if _, err := k.client.CreateDaemonSet(ctx, k.params.Namespace, k.generateAgentDaemonSet(), metav1.CreateOptions{}); err != nil {
		return err
	}

	k.Log("🚀 Creating Operator Deployment...")
	if _, err := k.client.CreateDeployment(ctx, k.params.Namespace, k.generateOperatorDeployment(), metav1.CreateOptions{}); err != nil {
		return err
	}

	if k.params.Wait {
		k.Log("⌛ Waiting for Cilium to be installed...")
		collector, err := status.NewK8sStatusCollector(ctx, k.client, status.K8sStatusParameters{
			Namespace:       k.params.Namespace,
			Wait:            true,
			WaitDuration:    k.params.WaitDuration,
			WarningFreePods: []string{defaults.AgentDaemonSetName, defaults.OperatorDeploymentName},
		})
		if err != nil {
			return err
		}

		s, err := collector.Status(ctx)
		if err != nil {
			if s != nil {
				fmt.Println(s.Format())
			}
			return err
		}
	}

	if k.params.RestartUnmanagedPods {
		if err := k.restartUnmanagedPods(ctx); err != nil {
			return err
		}
	}

	return nil
}
