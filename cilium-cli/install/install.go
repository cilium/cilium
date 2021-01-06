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

package install

import (
	"bytes"
	"context"
	"fmt"
	"io"

	"github.com/cilium/cilium-cli/defaults"
	"github.com/cilium/cilium-cli/internal/certs"
	"github.com/cilium/cilium-cli/internal/k8s"
	"github.com/cilium/cilium-cli/internal/utils"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
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
	initScriptMode                     = int32(0700)
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
			Verbs:     []string{"create", "list", "watch", "update"},
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

var nodeInitStartup = `
local err = 0
nsenter -t 1 -m -u -i -n -p -- bash -c "${STARTUP_SCRIPT}" && err=0 || err=$?
if [[ ${err} != 0 ]]; then
    echo "Node initialization failed with exit code '${err}'" 1>&2
    return 1
fi

echo "Node initialization successful"
`

var nodeInitStartupScript = `#!/bin/bash

set -o errexit
set -o pipefail
set -o nounset

mount | grep "/sys/fs/bpf type bpf" || {
echo "Mounting eBPF filesystem..."
mount bpffs /sys/fs/bpf -t bpf

which systemctl && {
echo "Installing BPF filesystem mount"
cat >/tmp/sys-fs-bpf.mount <<EOF
[Unit]
Description=Mount BPF filesystem (Cilium)
Documentation=http://docs.cilium.io/
DefaultDependencies=no
Before=local-fs.target umount.target
After=swap.target

[Mount]
What=bpffs
Where=/sys/fs/bpf
Type=bpf
Options=rw,nosuid,nodev,noexec,relatime,mode=700

[Install]
WantedBy=multi-user.target
EOF

if [ -d "/etc/systemd/system/" ]; then
  mv /tmp/sys-fs-bpf.mount /etc/systemd/system/
  echo "Installed sys-fs-bpf.mount to /etc/systemd/system/"
elif [ -d "/lib/systemd/system/" ]; then
  mv /tmp/sys-fs-bpf.mount /lib/systemd/system/
  echo "Installed sys-fs-bpf.mount to /lib/systemd/system/"
fi

systemctl enable sys-fs-bpf.mount
systemctl start sys-fs-bpf.mount
}
}

date > /tmp/cilium-bootstrap-time

rm -f /tmp/node-deinit.cilium.io
`

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
									Path: "/var/run/cilium",
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
									Path: "/opt/cni/bin",
									Type: &hostPathDirectoryOrCreate,
								},
							},
						},
						{
							// To install cilium cni configuration in the host
							Name: "etc-cni-netd",
							VolumeSource: corev1.VolumeSource{
								HostPath: &corev1.HostPathVolumeSource{
									Path: "/etc/cni/net.d",
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
														Key:  defaults.HubbleServerSecretCertName,
														Path: "server.crt",
													},
													{
														Key:  defaults.HubbleServerSecretKeyName,
														Path: "server.key",
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

	switch k.params.DatapathMode {
	case DatapathAwsENI:
		nodeInitContainer := corev1.Container{
			Name:            "node-init",
			Image:           k.fqAgentImage(),
			ImagePullPolicy: corev1.PullIfNotPresent,
			Command:         []string{"nsenter", "-t", "1", "-m", "-u", "-i", "-n", "-p", "--", "/tmp/node-init/node-init.sh"},
			SecurityContext: &corev1.SecurityContext{
				Capabilities: &corev1.Capabilities{
					Add: []corev1.Capability{"NET_ADMIN"},
				},
				Privileged: &varTrue,
			},
			VolumeMounts: []corev1.VolumeMount{
				{
					Name:      "node-init-script",
					MountPath: "/tmp/node-init",
				},
			},
			Resources: corev1.ResourceRequirements{
				Requests: corev1.ResourceList{
					corev1.ResourceCPU:    resource.MustParse("100m"),
					corev1.ResourceMemory: resource.MustParse("100Mi"),
				},
			},
		}

		ds.Spec.Template.Spec.InitContainers = append([]corev1.Container{nodeInitContainer}, ds.Spec.Template.Spec.InitContainers...)

		nodeInitVolume := corev1.Volume{
			Name: "node-init-script",
			VolumeSource: corev1.VolumeSource{
				ConfigMap: &corev1.ConfigMapVolumeSource{
					LocalObjectReference: corev1.LocalObjectReference{
						Name: "cilium-config",
					},
					Items: []corev1.KeyToPath{{
						Key:  "node-init-script",
						Path: "node-init.sh",
					}},
					DefaultMode: &initScriptMode,
				},
			},
		}

		ds.Spec.Template.Spec.Volumes = append(ds.Spec.Template.Spec.Volumes, nodeInitVolume)
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
	}

	return deployment
}

type k8sInstallerImplementation interface {
	CreateServiceAccount(ctx context.Context, namespace string, account *corev1.ServiceAccount, opts metav1.CreateOptions) (*corev1.ServiceAccount, error)
	DeleteServiceAccount(ctx context.Context, namespace, name string, opts metav1.DeleteOptions) error
	CreateConfigMap(ctx context.Context, namespace string, config *corev1.ConfigMap, opts metav1.CreateOptions) (*corev1.ConfigMap, error)
	DeleteConfigMap(ctx context.Context, namespace, name string, opts metav1.DeleteOptions) error
	CreateClusterRole(ctx context.Context, config *rbacv1.ClusterRole, opts metav1.CreateOptions) (*rbacv1.ClusterRole, error)
	DeleteClusterRole(ctx context.Context, name string, opts metav1.DeleteOptions) error
	CreateClusterRoleBinding(ctx context.Context, role *rbacv1.ClusterRoleBinding, opts metav1.CreateOptions) (*rbacv1.ClusterRoleBinding, error)
	DeleteClusterRoleBinding(ctx context.Context, name string, opts metav1.DeleteOptions) error
	CreateDaemonSet(ctx context.Context, namespace string, ds *appsv1.DaemonSet, opts metav1.CreateOptions) (*appsv1.DaemonSet, error)
	GetDaemonSet(ctx context.Context, namespace, name string, opts metav1.GetOptions) (*appsv1.DaemonSet, error)
	DeleteDaemonSet(ctx context.Context, namespace, name string, opts metav1.DeleteOptions) error
	CreateService(ctx context.Context, namespace string, service *corev1.Service, opts metav1.CreateOptions) (*corev1.Service, error)
	DeleteService(ctx context.Context, namespace, name string, opts metav1.DeleteOptions) error
	DeleteDeployment(ctx context.Context, namespace, name string, opts metav1.DeleteOptions) error
	CreateDeployment(ctx context.Context, namespace string, deployment *appsv1.Deployment, opts metav1.CreateOptions) (*appsv1.Deployment, error)
	GetDeployment(ctx context.Context, namespace, name string, opts metav1.GetOptions) (*appsv1.Deployment, error)
	DeploymentIsReady(ctx context.Context, namespace, deployment string) error
	DeleteNamespace(ctx context.Context, namespace string, opts metav1.DeleteOptions) error
	CreateNamespace(ctx context.Context, namespace string, opts metav1.CreateOptions) (*corev1.Namespace, error)
	GetNamespace(ctx context.Context, namespace string, options metav1.GetOptions) (*corev1.Namespace, error)
	ListPods(ctx context.Context, namespace string, options metav1.ListOptions) (*corev1.PodList, error)
	ExecInPod(ctx context.Context, namespace, pod, container string, command []string) (bytes.Buffer, error)
	CreateSecret(ctx context.Context, namespace string, secret *corev1.Secret, opts metav1.CreateOptions) (*corev1.Secret, error)
	DeleteSecret(ctx context.Context, namespace, name string, opts metav1.DeleteOptions) error
	GetSecret(ctx context.Context, namespace, name string, opts metav1.GetOptions) (*corev1.Secret, error)
	AutodetectFlavor(ctx context.Context) (k8s.Flavor, error)
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
)

type InstallParameters struct {
	Namespace     string
	Writer        io.Writer
	ClusterName   string
	DisableChecks []string
	Version       string
	AgentImage    string
	OperatorImage string

	DatapathMode string
	TunnelType   string
}

func (k *K8sInstaller) fqAgentImage() string {
	return utils.BuildImagePath(k.params.AgentImage, defaults.AgentImage, k.params.Version, defaults.Version)
}

func (k *K8sInstaller) fqOperatorImage() string {
	defaultImage := defaults.OperatorImage
	switch k.params.DatapathMode {
	case DatapathAwsENI:
		defaultImage = defaults.OperatorImageAWS
	}

	return utils.BuildImagePath(k.params.OperatorImage, defaultImage, k.params.Version, defaults.Version)
}

func (k *K8sInstaller) operatorCommand() []string {
	switch k.params.DatapathMode {
	case DatapathAwsENI:
		return []string{"cilium-operator-aws"}
	}

	return []string{"cilium-operator-generic"}
}

func NewK8sInstaller(client k8sInstallerImplementation, p InstallParameters) *K8sInstaller {
	cm := certs.NewCertManager(client, certs.Parameters{Namespace: p.Namespace})

	return &K8sInstaller{
		client:      client,
		params:      p,
		certManager: cm,
	}
}

func (k *K8sInstaller) Log(format string, a ...interface{}) {
	fmt.Fprintf(k.params.Writer, format+"\n", a...)
}

func (k *K8sInstaller) generateConfigMap() *corev1.ConfigMap {
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
			"wait-bpf-mount": "false",

			"masquerade":            "true",
			"enable-bpf-masquerade": "true",

			"enable-xt-socket-fallback": "true",
			"install-iptables-rules":    "true",

			"auto-direct-node-routes":                     "false",
			"enable-bandwidth-manager":                    "true",
			"enable-local-redirect-policy":                "false",
			"kube-proxy-replacement":                      "probe",
			"kube-proxy-replacement-healthz-bind-address": "",
			"enable-health-check-nodeport":                "true",
			"node-port-bind-protection":                   "true",
			"enable-auto-protect-node-port-range":         "true",
			"enable-session-affinity":                     "true",
			"enable-endpoint-health-checking":             "true",
			"enable-health-checking":                      "true",
			"enable-well-known-identities":                "false",
			"enable-remote-node-identity":                 "true",
			"operator-api-serve-addr":                     "127.0.0.1:9234",
			// Enable Hubble gRPC service.
			"enable-hubble": "true",
			// UNIX domain socket for Hubble server to listen to.
			"hubble-socket-path": defaults.HubbleSocketPath,
			// An additional address for Hubble server to listen to (e.g. ":4244").
			"hubble-listen-address":       ":4244",
			"hubble-disable-tls":          "false",
			"hubble-tls-cert-file":        "/var/lib/cilium/tls/hubble/server.crt",
			"hubble-tls-key-file":         "/var/lib/cilium/tls/hubble/server.key",
			"hubble-tls-client-ca-files":  "/var/lib/cilium/tls/hubble/client-ca.crt",
			"ipam":                        "cluster-pool",
			"cluster-pool-ipv4-cidr":      "10.0.0.0/8",
			"cluster-pool-ipv4-mask-size": "24",
			"disable-cnp-status-updates":  "true",
		},
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
		m.Data["ipam"] = "eni"
		// TODO(tgraf) Is this really sane?
		m.Data["egress-masquerade-interfaces"] = "eth0"

		m.Data["node-init-script"] = nodeInitStartupScript
	}

	return m
}

func (k *K8sInstaller) Install(ctx context.Context) error {
	if err := k.autodetectAndValidate(ctx); err != nil {
		return err
	}
	if err := k.installCerts(ctx); err != nil {
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
	}

	k.Log("🚀 Creating service accounts...")
	if _, err := k.client.CreateServiceAccount(ctx, k.params.Namespace, k8s.NewServiceAccount(defaults.AgentServiceAccountName), metav1.CreateOptions{}); err != nil {
		return err
	}

	if _, err := k.client.CreateServiceAccount(ctx, k.params.Namespace, k8s.NewServiceAccount(defaults.OperatorServiceAccountName), metav1.CreateOptions{}); err != nil {
		return err
	}

	k.Log("🚀 Creating cluster roles...")
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

	k.Log("🚀 Creating ConfigMap...")
	if _, err := k.client.CreateConfigMap(ctx, k.params.Namespace, k.generateConfigMap(), metav1.CreateOptions{}); err != nil {
		return err
	}

	k.Log("🚀 Creating agent DaemonSet...")
	if _, err := k.client.CreateDaemonSet(ctx, k.params.Namespace, k.generateAgentDaemonSet(), metav1.CreateOptions{}); err != nil {
		return err
	}

	k.Log("🚀 Creating operator Deployment...")
	if _, err := k.client.CreateDeployment(ctx, k.params.Namespace, k.generateOperatorDeployment(), metav1.CreateOptions{}); err != nil {
		return err
	}

	return nil
}
