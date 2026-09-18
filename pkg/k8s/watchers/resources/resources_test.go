// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/cache"

	cilium_api_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
)

func TestNormalizeMetadataDropsManagedFields(t *testing.T) {
	node := &cilium_api_v2.CiliumNode{
		ObjectMeta: metav1.ObjectMeta{
			Name:            "node-1",
			ResourceVersion: "42",
			Labels:          map[string]string{"app": "foo"},
			Annotations:     map[string]string{"io.cilium.network.ipv4-pod-cidr": "10.1.0.0/24"},
			OwnerReferences: []metav1.OwnerReference{{Name: "node-1", Kind: "Node"}},
			ManagedFields: []metav1.ManagedFieldsEntry{
				{Manager: "cilium-agent", Operation: metav1.ManagedFieldsOperationUpdate},
				{Manager: "cilium-operator-aws", Operation: metav1.ManagedFieldsOperationUpdate},
			},
		},
	}

	// Only managedFields goes: the rest of the metadata is what the stores are
	// indexed and the objects written back to the apiserver by.
	want := node.DeepCopy()
	want.ManagedFields = nil

	NormalizeMetadata(node)
	assert.Equal(t, want, node)
}

// The objects holding a slim ObjectMeta, either because that is what the slim
// clientset decodes or because a transform rebuilt them into one, have no
// managedFields and come out untouched.
func TestNormalizeMetadataSlimObject(t *testing.T) {
	pod := &slim_corev1.Pod{
		ObjectMeta: slim_metav1.ObjectMeta{
			Name:      "pod-1",
			Namespace: "default",
			Labels:    map[string]string{"app": "foo"},
		},
	}
	want := pod.DeepCopy()

	assert.NotPanics(t, func() { NormalizeMetadata(pod) })
	assert.Equal(t, want, pod)
}

// The deletions reported as tombstones hold no object to normalize.
func TestNormalizeMetadataTombstone(t *testing.T) {
	assert.NotPanics(t, func() {
		NormalizeMetadata(cache.DeletedFinalStateUnknown{Key: "default/pod-1"})
	})
}
