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
echo "Changing kubelet configuration to --network-plugin=cni --cni-bin-dir=/home/kubernetes/bin"
mkdir -p /home/kubernetes/bin
sed -i s#--network-plugin=kubenet#--network-plugin=cni\ --cni-bin-dir=/home/kubernetes/bin#g /etc/default/kubelet || true
echo "Restarting kubelet..."
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
