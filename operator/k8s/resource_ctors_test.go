// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package k8s

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
)

func fullPod() *slim_corev1.Pod {
	return &slim_corev1.Pod{
		TypeMeta: slim_metav1.TypeMeta{Kind: "Pod", APIVersion: "v1"},
		ObjectMeta: slim_metav1.ObjectMeta{
			Name:              "foo",
			Namespace:         "bar",
			UID:               "3f3e5b1a-0a0a-4e4e-8b8b-1c1c1c1c1c1c",
			ResourceVersion:   "42",
			GenerateName:      "foo-",
			Generation:        7,
			Labels:            map[string]string{"app": "foo"},
			Annotations:       map[string]string{"kubectl.kubernetes.io/last-applied-configuration": "{}"},
			DeletionTimestamp: &slim_metav1.Time{},
			OwnerReferences:   []slim_metav1.OwnerReference{{Name: "foo-rs"}},
		},
		Spec: slim_corev1.PodSpec{
			InitContainers: []slim_corev1.Container{
				{Name: "init", Ports: []slim_corev1.ContainerPort{{Name: "init-port", ContainerPort: 1}}},
			},
			Containers: []slim_corev1.Container{
				{Name: "sidecar"},
				{Name: "app", Ports: []slim_corev1.ContainerPort{
					{Name: "http", ContainerPort: 80, Protocol: slim_corev1.ProtocolTCP},
				}},
			},
			ServiceAccountName: "sa",
			NodeName:           "node-1",
			HostNetwork:        true,
		},
		Status: slim_corev1.PodStatus{
			Phase:             slim_corev1.PodPending,
			Conditions:        []slim_corev1.PodCondition{{Type: slim_corev1.PodReady}},
			HostIP:            "10.0.0.1",
			PodIP:             "10.1.0.1",
			PodIPs:            []slim_corev1.PodIP{{IP: "10.1.0.1"}},
			StartTime:         &slim_metav1.Time{},
			ContainerStatuses: []slim_corev1.ContainerStatus{{ContainerID: "containerd://abc"}},
			QOSClass:          slim_corev1.PodQOSBurstable,
		},
	}
}

// expectedPod is the field set the operator's consumers of PodResource read.
func expectedPod() *slim_corev1.Pod {
	return &slim_corev1.Pod{
		TypeMeta: slim_metav1.TypeMeta{Kind: "Pod", APIVersion: "v1"},
		ObjectMeta: slim_metav1.ObjectMeta{
			Name:            "foo",
			Namespace:       "bar",
			UID:             "3f3e5b1a-0a0a-4e4e-8b8b-1c1c1c1c1c1c",
			ResourceVersion: "42",
			Labels:          map[string]string{"app": "foo"},
		},
		Spec: slim_corev1.PodSpec{
			Containers: []slim_corev1.Container{
				{Ports: []slim_corev1.ContainerPort{
					{Name: "http", ContainerPort: 80, Protocol: slim_corev1.ProtocolTCP},
				}},
			},
			ServiceAccountName: "sa",
			NodeName:           "node-1",
			HostNetwork:        true,
		},
		Status: slim_corev1.PodStatus{
			Phase:  slim_corev1.PodPending,
			HostIP: "10.0.0.1",
			PodIPs: []slim_corev1.PodIP{{IP: "10.1.0.1"}},
		},
	}
}

func TestTransformToOperatorPod(t *testing.T) {
	pod := fullPod()

	stripped, err := TransformToOperatorPod(pod)
	require.NoError(t, err)
	assert.Equal(t, expectedPod(), stripped)

	// The source object is zeroed as a GC hint. The retained labels and ports
	// are unaffected, as the projection holds copies of their headers: the
	// assertion above would fail if it pointed into the source instead.
	assert.Equal(t, &slim_corev1.Pod{}, pod)
	assert.Equal(t, expectedPod(), stripped)
}

func fullNode() *slim_corev1.Node {
	return &slim_corev1.Node{
		TypeMeta: slim_metav1.TypeMeta{Kind: "Node", APIVersion: "v1"},
		ObjectMeta: slim_metav1.ObjectMeta{
			Name:              "node-1",
			UID:               "6d6d5b1a-0a0a-4e4e-8b8b-2c2c2c2c2c2c",
			ResourceVersion:   "42",
			GenerateName:      "node-",
			Generation:        7,
			Labels:            map[string]string{"topology.kubernetes.io/zone": "eu-west-1a"},
			Annotations:       map[string]string{"csi.volume.kubernetes.io/nodeid": "{}"},
			DeletionTimestamp: &slim_metav1.Time{},
			OwnerReferences:   []slim_metav1.OwnerReference{{Name: "some-owner"}},
		},
		Spec: slim_corev1.NodeSpec{
			PodCIDR:    "10.1.0.0/24",
			PodCIDRs:   []string{"10.1.0.0/24"},
			ProviderID: "aws:///eu-west-1a/i-0123456789abcdef0",
			Taints: []slim_corev1.Taint{
				{Key: "node.cilium.io/agent-not-ready", Value: "true", Effect: slim_corev1.TaintEffectNoSchedule},
			},
		},
		Status: slim_corev1.NodeStatus{
			Conditions: []slim_corev1.NodeCondition{
				{Type: slim_corev1.NodeReady, Status: slim_corev1.ConditionTrue, Reason: "KubeletReady"},
			},
			Addresses: []slim_corev1.NodeAddress{
				{Type: slim_corev1.NodeInternalIP, Address: "10.0.0.1"},
			},
		},
	}
}

// expectedNode is the field set the operator's consumers of NodeResource read.
func expectedNode() *slim_corev1.Node {
	return &slim_corev1.Node{
		TypeMeta: slim_metav1.TypeMeta{Kind: "Node", APIVersion: "v1"},
		ObjectMeta: slim_metav1.ObjectMeta{
			Name:            "node-1",
			ResourceVersion: "42",
		},
		Spec: slim_corev1.NodeSpec{
			Taints: []slim_corev1.Taint{
				{Key: "node.cilium.io/agent-not-ready", Value: "true", Effect: slim_corev1.TaintEffectNoSchedule},
			},
		},
		Status: slim_corev1.NodeStatus{
			Conditions: []slim_corev1.NodeCondition{
				{Type: slim_corev1.NodeReady, Status: slim_corev1.ConditionTrue, Reason: "KubeletReady"},
			},
		},
	}
}

func TestTransformToOperatorNode(t *testing.T) {
	node := fullNode()

	stripped, err := TransformToOperatorNode(node)
	require.NoError(t, err)
	assert.Equal(t, expectedNode(), stripped)

	// The source object is zeroed as a GC hint. The retained taints and
	// conditions are unaffected, as the projection holds copies of their slice
	// headers: the assertion above would fail if it pointed into the source
	// instead.
	assert.Equal(t, &slim_corev1.Node{}, node)
	assert.Equal(t, expectedNode(), stripped)
}
