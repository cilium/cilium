/*
Copyright 2023 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package conformance

import (
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/mcs-api/pkg/apis/v1alpha1"
)

const helloServiceName = "hello"

func newHelloService() *corev1.Service {
	return &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:        helloServiceName,
			Annotations: map[string]string{"dummy-svc": "dummy"},
			Labels:      map[string]string{"dummy-svc": "dummy"},
		},
		Spec: corev1.ServiceSpec{
			Selector: map[string]string{
				"app": helloServiceName,
			},
			Ports: []corev1.ServicePort{
				{
					Name:     "tcp",
					Port:     42,
					Protocol: corev1.ProtocolTCP,
				},
				{
					Name:     "udp",
					Port:     42,
					Protocol: corev1.ProtocolUDP,
				},
			},
			SessionAffinity: corev1.ServiceAffinityClientIP,
			SessionAffinityConfig: &corev1.SessionAffinityConfig{
				ClientIP: &corev1.ClientIPConfig{TimeoutSeconds: ptr.To(int32(10))},
			},
			IPFamilyPolicy: ptr.To(corev1.IPFamilyPolicyPreferDualStack),
		},
	}
}

func newHelloServiceExport() *v1alpha1.ServiceExport {
	return &v1alpha1.ServiceExport{
		ObjectMeta: metav1.ObjectMeta{
			Name:        helloServiceName,
			Annotations: map[string]string{"dummy-svcexport": "dummy"},
			Labels:      map[string]string{"dummy-svcexport": "dummy"},
		},
	}
}

// socatListenerScript generates a shell script that detects the pod's IP family configuration
// and starts the appropriate socat listener (IPv4, IPv6, or dual-stack).
func socatListenerScript(protocol string) string {
	return `# Detect IP families available on the pod from podIPs
# The downward API provides podIPs as a plain string (single IP or space/comma-separated list)
has_ipv4=false
has_ipv6=false

# Check for IPv4 pattern (dotted decimal notation)
if echo "$MY_POD_IPS" | grep -qE '([^0-9]|^)[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}([^0-9]|$)'; then has_ipv4=true; fi

# Check for IPv6 pattern (hex digits with at least two colons)
if echo "$MY_POD_IPS" | grep -qE '[0-9a-fA-F]*:[0-9a-fA-F]*:[0-9a-fA-F:]*'; then has_ipv6=true; fi

# Debug: log what we detected
echo "DEBUG: MY_POD_IPS=$MY_POD_IPS" >&2
echo "DEBUG: has_ipv4=$has_ipv4, has_ipv6=$has_ipv6" >&2

# Extract first IP address (may be space or comma separated)
first_ip=$(echo "$MY_POD_IPS" | tr ',' ' ' | awk '{print $1}')
echo "DEBUG: first_ip=$first_ip" >&2

# Choose socat listener based on available IP families
# Export first_ip so it's available to SYSTEM subprocesses
export first_ip

if $has_ipv6 && $has_ipv4; then
	# Dual-stack: use IPv6 socket that accepts both
	echo "DEBUG: Starting dual-stack listener" >&2
	socat -v -v ` + protocol + `6-LISTEN:42,crlf,reuseaddr,fork,ipv6only=0 SYSTEM:'echo "pod ip $first_ip"'
elif $has_ipv6; then
	# IPv6 only
	echo "DEBUG: Starting IPv6-only listener" >&2
	socat -v -v ` + protocol + `6-LISTEN:42,crlf,reuseaddr,fork SYSTEM:'echo "pod ip $first_ip"'
else
	# IPv4 only
	echo "DEBUG: Starting IPv4-only listener" >&2
	socat -v -v ` + protocol + `-LISTEN:42,crlf,reuseaddr,fork SYSTEM:'echo "pod ip $first_ip"'
fi`
}

func podContainers() []corev1.Container {
	return []corev1.Container{
		{
			Name:  "hello-tcp",
			Image: "alpine/socat:1.7.4.4",
			// Detect if pod has IPv4, IPv6, or both and use appropriate socat listener
			// - IPv4 only: use TCP-LISTEN
			// - IPv6 only: use TCP6-LISTEN (no ipv6only flag needed)
			// - Dual-stack: use TCP6-LISTEN with ipv6only=0 to handle both
			Command: []string{"/bin/sh"},
			Args:    []string{"-c", socatListenerScript("TCP")},
			Env: []corev1.EnvVar{
				{
					Name: "MY_POD_IPS",
					ValueFrom: &corev1.EnvVarSource{
						FieldRef: &corev1.ObjectFieldSelector{
							FieldPath: "status.podIPs",
						},
					},
				},
			},
		},
		{
			Name:  "hello-udp",
			Image: "alpine/socat:1.7.4.4",
			// Detect if pod has IPv4, IPv6, or both and use appropriate socat listener
			// - IPv4 only: use UDP-LISTEN
			// - IPv6 only: use UDP6-LISTEN (no ipv6only flag needed)
			// - Dual-stack: use UDP6-LISTEN with ipv6only=0 to handle both
			Command: []string{"/bin/sh"},
			Args:    []string{"-c", socatListenerScript("UDP")},
			Env: []corev1.EnvVar{
				{
					Name: "MY_POD_IPS",
					ValueFrom: &corev1.EnvVarSource{
						FieldRef: &corev1.ObjectFieldSelector{
							FieldPath: "status.podIPs",
						},
					},
				},
			},
		},
	}
}

func newHelloDeployment() *appsv1.Deployment {
	return &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name: helloServiceName,
		},
		Spec: appsv1.DeploymentSpec{
			Replicas: ptr.To(int32(1)),
			Selector: &metav1.LabelSelector{
				MatchLabels: map[string]string{
					"app": helloServiceName,
				},
			},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: map[string]string{"app": helloServiceName},
				},
				Spec: corev1.PodSpec{
					Containers: podContainers(),
				},
			},
		},
	}
}

func newStatefulSet(replicas int) *appsv1.StatefulSet {
	return &appsv1.StatefulSet{
		ObjectMeta: metav1.ObjectMeta{
			Name: helloServiceName + "-ss",
		},
		Spec: appsv1.StatefulSetSpec{
			Selector: &metav1.LabelSelector{
				MatchLabels: map[string]string{
					"app": helloServiceName,
				},
			},
			ServiceName: helloServiceName,
			Replicas:    ptr.To(int32(replicas)),
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: map[string]string{
						"app": helloServiceName,
					},
				},
				Spec: corev1.PodSpec{
					Containers:    podContainers(),
					RestartPolicy: corev1.RestartPolicyAlways,
				},
			},
		},
	}
}

func newRequestPod() *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:   "request",
			Labels: map[string]string{"app": "request"},
		},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{
				{
					Name:  "request",
					Image: "nicolaka/netshoot:v0.15",
					Args:  []string{"/bin/sh", "-ec", "while :; do echo '.'; sleep 5 ; done"},
				},
			},
		},
	}
}
