// Copyright 2021 Authors of Cilium
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
	"context"
	"fmt"
	"os/exec"
	"strings"

	"github.com/cilium/cilium-cli/defaults"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	gkeInitName = "cilium-gke-node-init"
)

var gkeInitLabels = map[string]string{
	"k8s-app": "cilium-gke-node-init",
}

func (k *K8sInstaller) gkeNativeRoutingCIDR(ctx context.Context, contextName string) (string, error) {
	// Example: gke_cilium-dev_us-west2-a_tgraf-cluster1
	parts := strings.Split(contextName, "_")
	if len(parts) < 4 {
		return "", fmt.Errorf("unable to derive region and zone from context name %q: not in the form gke_PROJECT_ZONE_NAME", contextName)
	}

	args := []string{"container", "clusters", "describe", parts[3], "--zone", parts[2], "--format", "value(clusterIpv4Cidr)"}
	result := exec.Command("gcloud", args...)
	bytes, err := result.Output()
	if err != nil {
		return "", fmt.Errorf("unable to execute gcloud %s to extract native routing CIDR: %w", args, err)
	}

	cidr := strings.TrimSuffix(string(bytes), "\n")
	k.Log("✅ Detected GKE native routing CIDR: %s", cidr)

	return cidr, nil
}

var nodeInitStartupScriptGKE = `#!/bin/bash

set -o errexit
set -o pipefail
set -o nounset

echo "Changing kubelet configuration to --network-plugin=cni --cni-bin-dir=/home/kubernetes/bin"
mkdir -p /home/kubernetes/bin
sed -i s#--network-plugin=kubenet#--network-plugin=cni\ --cni-bin-dir=/home/kubernetes/bin#g /etc/default/kubelet || true
echo "Restarting kubelet..."
systemctl restart kubelet

iptables -w -t nat -D POSTROUTING -m comment --comment "ip-masq: ensure nat POSTROUTING directs all non-LOCAL destination traffic to our custom IP-MASQ chain" -m addrtype ! --dst-type LOCAL -j IP-MASQ || true

mkdir -p /tmp/cilium-bootstrap
date > /tmp/cilium-bootstrap/time
`

func (k *K8sInstaller) generateGKEInitDaemonSet() *appsv1.DaemonSet {
	ds := &appsv1.DaemonSet{
		ObjectMeta: metav1.ObjectMeta{
			Name:   gkeInitName,
			Labels: gkeInitLabels,
		},
		Spec: appsv1.DaemonSetSpec{
			Selector: &metav1.LabelSelector{
				MatchLabels: gkeInitLabels,
			},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Name:   gkeInitName,
					Labels: gkeInitLabels,
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
											Key: "gke-node-init-script",
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
