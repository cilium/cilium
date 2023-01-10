// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package k8s

import (
	"reflect"
	"testing"

	"github.com/stretchr/testify/require"

	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
)

func TestGetPodMetadata(t *testing.T) {
	ns := &slim_corev1.Namespace{
		ObjectMeta: slim_metav1.ObjectMeta{
			Labels: map[string]string{
				"kubernetes.io/metadata.name": "default",
				"namespace-level-key":         "namespace-level-value",
			},
		},
	}

	pod := &slim_corev1.Pod{
		ObjectMeta: slim_metav1.ObjectMeta{
			Namespace: "default",
			Labels: map[string]string{
				"app":                         "test",
				"io.kubernetes.pod.namespace": "default",
			},
			Annotations: map[string]string{},
		},
	}

	expectedLabels := map[string]string{
		"app":                          "test",
		"io.cilium.k8s.policy.cluster": "",
		"io.kubernetes.pod.namespace":  "default",
		"io.cilium.k8s.namespace.labels.kubernetes.io/metadata.name": "default",
		"io.cilium.k8s.namespace.labels.namespace-level-key":         "namespace-level-value",
	}

	t.Run("normal scenario", func(t *testing.T) {
		pod := pod.DeepCopy()

		_, labels, _, err := GetPodMetadata(ns, pod)

		require.NoError(t, err)
		require.Equal(t, expectedLabels, labels)
	})

	t.Run("pod labels contains cilium owned label", func(t *testing.T) {
		t.Run("override namespace labels", func(t *testing.T) {
			pod := pod.DeepCopy()
			pod.Labels["io.cilium.k8s.namespace.labels.namespace-level-key"] = "override-namespace-level-value"

			_, labels, _, err := GetPodMetadata(ns, pod)

			require.NoError(t, err)
			require.Equal(t, expectedLabels, labels)
		})

		t.Run("add one more namespace labels", func(t *testing.T) {
			pod := pod.DeepCopy()
			pod.Labels["io.cilium.k8s.namespace.labels.another-namespace-key"] = "another-namespace-level-value"

			_, labels, _, err := GetPodMetadata(ns, pod)

			require.NoError(t, err)
			require.Equal(t, expectedLabels, labels)
		})
	})

	t.Run("istio sidecar label", func(t *testing.T) {
		t.Run("with istio sidecar label", func(t *testing.T) {
			pod := pod.DeepCopy()
			pod.Labels["io.cilium.k8s.policy.istiosidecarproxy"] = "true"

			_, labels, _, err := GetPodMetadata(ns, pod)

			require.NoError(t, err)
			require.Equal(t, map[string]string{
				"app":                          "test",
				"io.cilium.k8s.policy.cluster": "",
				"io.kubernetes.pod.namespace":  "default",
				"io.cilium.k8s.namespace.labels.kubernetes.io/metadata.name": "default",
				"io.cilium.k8s.namespace.labels.namespace-level-key":         "namespace-level-value",
				"io.cilium.k8s.policy.istiosidecarproxy":                     "true",
			}, labels)
		})

		t.Run("with istio sidecar injection", func(t *testing.T) {
			pod := pod.DeepCopy()
			pod.Annotations["sidecar.istio.io/status"] = "true"
			pod.Spec.Containers = []slim_corev1.Container{
				{
					Name:  "istio-proxy",
					Image: "cilium/istio_proxy:1.0.0",
					VolumeMounts: []slim_corev1.VolumeMount{
						{
							MountPath: "/var/run/cilium",
						},
					},
				},
			}

			_, labels, _, err := GetPodMetadata(ns, pod)

			require.NoError(t, err)
			require.Equal(t, map[string]string{
				"app":                          "test",
				"io.cilium.k8s.policy.cluster": "",
				"io.kubernetes.pod.namespace":  "default",
				"io.cilium.k8s.namespace.labels.kubernetes.io/metadata.name": "default",
				"io.cilium.k8s.namespace.labels.namespace-level-key":         "namespace-level-value",
				"io.cilium.k8s.policy.istiosidecarproxy":                     "true",
			}, labels)
		})
	})
}

func Test_filterPodLabels(t *testing.T) {
	expectedLabels := map[string]string{
		"app":                         "test",
		"io.kubernetes.pod.namespace": "default",
	}
	type args struct {
		labels map[string]string
	}
	tests := []struct {
		name string
		args args
		want map[string]string
	}{
		{
			name: "normal scenario",
			args: args{
				labels: map[string]string{
					"app":                         "test",
					"io.kubernetes.pod.namespace": "default",
				},
			},
			want: expectedLabels,
		},
		{
			name: "having cilium owned namespace labels",
			args: args{
				labels: map[string]string{
					"app":                         "test",
					"io.kubernetes.pod.namespace": "default",
					"io.cilium.k8s.namespace.labels.foo.bar/baz":                 "malicious-pod-level-override",
					"io.cilium.k8s.namespace.labels.kubernetes.io/metadata.name": "kube-system",
				},
			},
			want: expectedLabels,
		},
		{
			name: "having cilium owned policy labels",
			args: args{
				labels: map[string]string{
					"app":                                    "test",
					"io.kubernetes.pod.namespace":            "default",
					"io.cilium.k8s.policy.name":              "admin",
					"io.cilium.k8s.policy.cluster":           "admin-cluster",
					"io.cilium.k8s.policy.derived-from":      "admin",
					"io.cilium.k8s.policy.namespace":         "kube-system",
					"io.cilium.k8s.policy.istiosidecarproxy": "false",
					"io.cilium.k8s.policy.serviceaccount":    "admin-serviceaccount",
					"io.cilium.k8s.policy.uuid":              "6eadee3e-0121-11ed-b58d-fc3497a92ef6",
				},
			},
			want: map[string]string{
				"app":                         "test",
				"io.kubernetes.pod.namespace": "default",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := filterPodLabels(tt.args.labels); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("filterPodLabels() = %v, want %v", got, tt.want)
			}
		})
	}
}
