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
