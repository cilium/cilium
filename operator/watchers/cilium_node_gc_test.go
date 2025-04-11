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
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/tools/cache"

	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/k8s/client/clientset/versioned/fake"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
)

func Test_performCiliumNodeGC(t *testing.T) {
	cns := []runtime.Object{
		&v2.CiliumNode{
			ObjectMeta: metav1.ObjectMeta{
				Name: "valid-node",
			},
		},
		&v2.CiliumNode{
			ObjectMeta: metav1.ObjectMeta{
				Name: "invalid-node",
			},
		},
		&v2.CiliumNode{
			ObjectMeta: metav1.ObjectMeta{
				Name:            "invalid-node-with-owner-ref",
				OwnerReferences: []metav1.OwnerReference{{}},
			},
		},
		&v2.CiliumNode{
			ObjectMeta: metav1.ObjectMeta{
				Name:        "invalid-node-with-annotation",
				Annotations: map[string]string{skipGCAnnotationKey: "true"},
			},
		},
	}

	fcn := fake.NewSimpleClientset(cns...).CiliumV2().CiliumNodes()
	fCNStore := cache.NewStore(cache.MetaNamespaceKeyFunc)
	for _, cn := range cns {
		fCNStore.Add(cn)
	}

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
	err := performCiliumNodeGC(t.Context(), fcn, fCNStore, fng, interval, candidateStore, hivetest.Logger(t))
	assert.NoError(t, err)
	assert.Len(t, candidateStore.nodesToRemove, 1)
	_, exists := candidateStore.nodesToRemove["invalid-node"]
	assert.True(t, exists)

	// check if the invalid node is actually GC-ed
	time.Sleep(interval)
	err = performCiliumNodeGC(t.Context(), fcn, fCNStore, fng, interval, candidateStore, hivetest.Logger(t))
	assert.NoError(t, err)
	assert.Empty(t, candidateStore.nodesToRemove)
	_, exists = candidateStore.nodesToRemove["invalid-node"]
	assert.False(t, exists)
}
