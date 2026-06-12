// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package k8s

import (
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"

	ciliumio "github.com/cilium/cilium/pkg/k8s/apis/cilium.io"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	ciliumLabels "github.com/cilium/cilium/pkg/labels"
	ciliumTypes "github.com/cilium/cilium/pkg/types"
	"github.com/cilium/cilium/pkg/u8proto"
)

func TestGetPodMetadata(t *testing.T) {
	ns := &slim_corev1.Namespace{
		ObjectMeta: slim_metav1.ObjectMeta{
			Name: "default",
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

		_, labels := GetPodMetadata(hivetest.Logger(t), ns, pod)
		require.Equal(t, expectedLabels, labels)
	})

	t.Run("pod labels contains cilium owned label", func(t *testing.T) {
		t.Run("override namespace labels", func(t *testing.T) {
			pod := pod.DeepCopy()
			pod.Labels["io.cilium.k8s.namespace.labels.namespace-level-key"] = "override-namespace-level-value"

			_, labels := GetPodMetadata(hivetest.Logger(t), ns, pod)
			require.Equal(t, expectedLabels, labels)
		})

		t.Run("add one more namespace labels", func(t *testing.T) {
			pod := pod.DeepCopy()
			pod.Labels["io.cilium.k8s.namespace.labels.another-namespace-key"] = "another-namespace-level-value"

			_, labels := GetPodMetadata(hivetest.Logger(t), ns, pod)
			require.Equal(t, expectedLabels, labels)
		})
	})

	t.Run("named ports metadata", func(t *testing.T) {
		pod := pod.DeepCopy()
		pod.Labels[ciliumio.NamedPortsIdentityLabelName] = "spoofed"
		pod.Labels[ciliumio.NamedPortsIdentityLabelNameForIndex(1)] = "spoofed"
		pod.Spec.Containers = []slim_corev1.Container{{
			Ports: []slim_corev1.ContainerPort{
				{Name: "https", ContainerPort: 443, Protocol: slim_corev1.ProtocolTCP},
				{Name: "dns", ContainerPort: 53, Protocol: slim_corev1.ProtocolUDP},
				{Name: "http", ContainerPort: 80, Protocol: slim_corev1.ProtocolTCP},
				{Name: "", ContainerPort: 8080, Protocol: slim_corev1.ProtocolTCP},
			},
		}}

		namedPorts, labels := GetPodMetadata(hivetest.Logger(t), ns, pod)
		require.Equal(t, ciliumTypes.NamedPortMap{
			"dns":   {Port: 53, Proto: u8proto.UDP},
			"http":  {Port: 80, Proto: u8proto.TCP},
			"https": {Port: 443, Proto: u8proto.TCP},
		}, namedPorts)
		require.Equal(t, expectedLabels, labels)
	})
}

func TestNamedPortsIdentityLabels(t *testing.T) {
	labelArray := NamedPortsIdentityLabels(ciliumTypes.NamedPortMap{
		"https": {Port: 443, Proto: u8proto.TCP},
		"dns":   {Port: 53, Proto: u8proto.UDP},
		"http":  {Port: 80, Proto: u8proto.TCP},
	})
	require.Equal(t, ciliumLabels.LabelArray{ciliumLabels.NewLabel(
		ciliumio.NamedPortsIdentityLabelName,
		"dns.UDP.53_http.TCP.80_https.TCP.443",
		ciliumLabels.LabelSourceGenerated,
	)}, labelArray)

	labelArray = NamedPortsIdentityLabels(ciliumTypes.NamedPortMap{
		"port-a": {Port: 8000, Proto: u8proto.TCP},
		"port-b": {Port: 8001, Proto: u8proto.TCP},
		"port-c": {Port: 8002, Proto: u8proto.TCP},
		"port-d": {Port: 8003, Proto: u8proto.TCP},
		"port-e": {Port: 8004, Proto: u8proto.TCP},
	})
	require.Equal(t, ciliumLabels.LabelArray{
		ciliumLabels.NewLabel(
			ciliumio.NamedPortsIdentityLabelName,
			"port-a.TCP.8000_port-b.TCP.8001_port-c.TCP.8002_port-d.TCP.8003",
			ciliumLabels.LabelSourceGenerated,
		),
		ciliumLabels.NewLabel(
			ciliumio.NamedPortsIdentityLabelNameForIndex(1),
			"port-e.TCP.8004",
			ciliumLabels.LabelSourceGenerated,
		),
	}, labelArray)

	require.Empty(t, NamedPortsIdentityLabels(nil))
}
