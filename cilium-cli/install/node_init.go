// SPDX-License-Identifier: Apache-2.0
// Copyright 2021 Authors of Cilium

package install

import (
	"strings"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/cilium/cilium-cli/defaults"
	"github.com/cilium/cilium-cli/internal/k8s"
)

var (
	nodeInitScript = map[k8s.Kind]string{
		k8s.KindEKS: bash(`
# When running in AWS ENI mode, it's likely that 'aws-node' has
# had a chance to install SNAT iptables rules. These can result
# in dropped traffic, so we should attempt to remove them.
# We do it using a 'postStart' hook since this may need to run
# for nodes which might have already been init'ed but may still
# have dangling rules. This is safe because there are no
# dependencies on anything that is part of the startup script
# itself, and can be safely run multiple times per node (e.g. in
# case of a restart).
if [[ "$(iptables-save | grep -c AWS-SNAT-CHAIN)" != "0" ]];
then
	echo 'Deleting iptables rules created by the AWS CNI VPC plugin'
	iptables-save | grep -v AWS-SNAT-CHAIN | iptables-restore
fi
echo 'Done!'
`),
		k8s.KindGKE: bash(`
# Check if we're running on a GKE containerd flavor.
GKE_KUBERNETES_BIN_DIR="/home/kubernetes/bin"
if [[ -f "${GKE_KUBERNETES_BIN_DIR}/gke" ]] && command -v containerd &>/dev/null; then
	echo "GKE *_containerd flavor detected..."

	# (GKE *_containerd) Upon node restarts, GKE's containerd images seem to reset
	# the /etc directory and our changes to the kubelet and Cilium's CNI
	# configuration are removed. This leaves room for containerd and its CNI to
	# take over pods previously managed by Cilium, causing Cilium to lose
	# ownership over these pods. We rely on the empirical observation that
	# /home/kubernetes/bin/kubelet is not changed across node reboots, and replace
	# it with a wrapper script that performs some initialization steps when
	# required and then hands over control to the real kubelet.

	# Only create the kubelet wrapper if we haven't previously done so.
	if [[ ! -f "${GKE_KUBERNETES_BIN_DIR}/the-kubelet" ]];
	then
	echo "Installing the kubelet wrapper..."

	# Rename the real kubelet.
	mv "${GKE_KUBERNETES_BIN_DIR}/kubelet" "${GKE_KUBERNETES_BIN_DIR}/the-kubelet"

	# Initialize the kubelet wrapper which lives in the place of the real kubelet.
	touch "${GKE_KUBERNETES_BIN_DIR}/kubelet"
	chmod a+x "${GKE_KUBERNETES_BIN_DIR}/kubelet"

	# Populate the kubelet wrapper. It will perform the initialization steps we
	# need and then become the kubelet.
	cat <<'EOF' | tee "${GKE_KUBERNETES_BIN_DIR}/kubelet"
#!/bin/bash
set -euo pipefail
CNI_CONF_DIR="/etc/cni/net.d"
CONTAINERD_CONFIG="/etc/containerd/config.toml"
# Only stop and start containerd if the Cilium CNI configuration does not exist,
# or if the 'conf_template' property is present in the containerd config file,
# in order to avoid unnecessarily restarting containerd.
if [[ -z "$(find "${CNI_CONF_DIR}" -type f -name '*cilium*')" || \
		"$(grep -cE '^\s+conf_template' "${CONTAINERD_CONFIG}")" != "0" ]];
then
	# Stop containerd as it starts by creating a CNI configuration from a template
	# causing pods to start with IPs assigned by GKE's CNI.
	# 'disable --now' is used instead of stop as this script runs concurrently
	# with containerd on node startup, and hence containerd might not have been
	# started yet, in which case 'disable' prevents it from starting.
	echo "Disabling and stopping containerd"
	systemctl disable --now containerd
	# Remove any pre-existing files in the CNI configuration directory. We skip
	# any possibly existing Cilium configuration file for the obvious reasons.
	echo "Removing undesired CNI configuration files"
	find "${CNI_CONF_DIR}" -type f -not -name '*cilium*' -exec rm {} \;
	# As mentioned above, the containerd configuration needs a little tweak in
	# order not to create the default CNI configuration, so we update its config.
	echo "Fixing containerd configuration"
	sed -Ei 's/^(\s+conf_template)/\#\1/g' "${CONTAINERD_CONFIG}"
	# Start containerd. It won't create it's CNI configuration file anymore.
	echo "Enabling and starting containerd"
	systemctl enable --now containerd
fi
# Become the real kubelet, and pass it some additionally required flags (and
# place these last so they have precedence).
exec /home/kubernetes/bin/the-kubelet "${@}" --network-plugin=cni --cni-bin-dir={{ .Values.cni.binPath }}
EOF
	else
	echo "Kubelet wrapper already exists, skipping..."
	fi
else
	# (Generic) Alter the kubelet configuration to run in CNI mode
	echo "Changing kubelet configuration to --network-plugin=cni --cni-bin-dir={{ .Values.cni.binPath }}"
	mkdir -p {{ .Values.cni.binPath }}
	sed -i "s:--network-plugin=kubenet:--network-plugin=cni\ --cni-bin-dir={{ .Values.cni.binPath }}:g" /etc/default/kubelet
fi
echo "Restarting the kubelet..."
systemctl restart kubelet

iptables -w -t nat -D POSTROUTING -m comment --comment "ip-masq: ensure nat POSTROUTING directs all non-LOCAL destination traffic to our custom IP-MASQ chain" -m addrtype ! --dst-type LOCAL -j IP-MASQ || true

mkdir -p /tmp/cilium-bootstrap
date > /tmp/cilium-bootstrap/time
`)}
)

func nodeInitLabels(k k8s.Kind) map[string]string {
	return map[string]string{
		"k8s-app": nodeInitName(k),
	}
}

func nodeInitName(k k8s.Kind) string {
	return "cilium-" + strings.ToLower(k.String()) + "-node-init"
}

func nodeInitScriptConfigMapKey(k k8s.Kind) string {
	return strings.ToLower(k.String()) + "-node-init-script"
}

func (k *K8sInstaller) generateNodeInitDaemonSet(kind k8s.Kind) *appsv1.DaemonSet {
	ds := &appsv1.DaemonSet{
		ObjectMeta: metav1.ObjectMeta{
			Name:   nodeInitName(kind),
			Labels: nodeInitLabels(kind),
		},
		Spec: appsv1.DaemonSetSpec{
			Selector: &metav1.LabelSelector{
				MatchLabels: nodeInitLabels(kind),
			},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Name:   nodeInitName(kind),
					Labels: nodeInitLabels(kind),
				},
				Spec: corev1.PodSpec{
					HostNetwork:                   true,
					HostPID:                       true,
					RestartPolicy:                 corev1.RestartPolicyAlways,
					PriorityClassName:             "system-node-critical",
					ServiceAccountName:            defaults.AgentServiceAccountName,
					TerminationGracePeriodSeconds: &agentTerminationGracePeriodSeconds,
					Tolerations: []corev1.Toleration{
						{Operator: corev1.TolerationOpExists},
					},
					Containers: []corev1.Container{
						{
							Name:            "node-init",
							Image:           "quay.io/cilium/startup-script:62bfbe88c17778aad7bef9fa57ff9e2d4a9ba0d8",
							ImagePullPolicy: corev1.PullIfNotPresent,
							SecurityContext: &corev1.SecurityContext{
								Capabilities: &corev1.Capabilities{
									Add: []corev1.Capability{"NET_ADMIN"},
								},
								Privileged: &varTrue,
							},
							Env: []corev1.EnvVar{
								{
									Name:  "CHECKPOINT_PATH",
									Value: "/tmp/node-init.cilium.io",
								},
								{
									Name: "STARTUP_SCRIPT",
									ValueFrom: &corev1.EnvVarSource{
										ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
											LocalObjectReference: corev1.LocalObjectReference{
												Name: defaults.ConfigMapName,
											},
											Key: nodeInitScriptConfigMapKey(kind),
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
	return ds
}

func bash(v string) string {
	return `#!/bin/bash

set -o errexit
set -o pipefail
set -o nounset
	
` + v
}
