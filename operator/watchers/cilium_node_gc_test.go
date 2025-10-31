// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package watchers

import (
	"testing"
	"time"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/assert"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"

	operatorK8s "github.com/cilium/cilium/operator/k8s"
	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client/testutils"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
)

func Test_performCiliumNodeGC(t *testing.T) {
	cns := []*v2.CiliumNode{
		{
			ObjectMeta: metav1.ObjectMeta{
				Name: "valid-node",
			},
		}, {
			ObjectMeta: metav1.ObjectMeta{
				Name: "invalid-node",
			},
		}, {
			ObjectMeta: metav1.ObjectMeta{
				Name:            "invalid-node-with-owner-ref",
				OwnerReferences: []metav1.OwnerReference{{}},
			},
		}, {
			ObjectMeta: metav1.ObjectMeta{
				Name:        "invalid-node-with-annotation",
				Annotations: map[string]string{skipGCAnnotationKey: "true"},
			},
		},
	}

	_, cs := k8sClient.NewFakeClientset(hivetest.Logger(t))
	fcn := cs.CiliumV2().CiliumNodes()
	for _, cn := range cns {
		_, err := fcn.Create(t.Context(), cn, metav1.CreateOptions{})
		assert.NoError(t, err)
	}

	ciliumNodes, err := operatorK8s.CiliumNodeResource(hivetest.Lifecycle(t), cs, nil)
	assert.NoError(t, err)

	store, err := ciliumNodes.Store(t.Context())
	assert.NoError(t, err)

	interval := time.Nanosecond
	fng := &fakeNodeGetter{
		OnGetK8sSlimNode: func(nodeName string) (*slim_corev1.Node, error) {
			if nodeName == "valid-node" {
				return &slim_corev1.Node{}, nil
			}
			return nil, k8serrors.NewNotFound(schema.GroupResource{}, "invalid-node")
		},
	}

	candidateStore := newCiliumNodeGCCandidate()

	// check if the invalid node is added to GC candidate
	err = performCiliumNodeGC(t.Context(), fcn, store, fng, interval, candidateStore, hivetest.Logger(t))
	assert.NoError(t, err)
	assert.Len(t, candidateStore.nodesToRemove, 1)
	_, exists := candidateStore.nodesToRemove["invalid-node"]
	assert.True(t, exists)

	// check if the invalid node is actually GC-ed
	time.Sleep(interval)
	err = performCiliumNodeGC(t.Context(), fcn, store, fng, interval, candidateStore, hivetest.Logger(t))
	assert.NoError(t, err)
	assert.Empty(t, candidateStore.nodesToRemove)
	_, exists = candidateStore.nodesToRemove["invalid-node"]
	assert.False(t, exists)
}
