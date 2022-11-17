// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package watchers

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/tools/cache"

	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/k8s/client/clientset/versioned/fake"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
)

func Test_performCiliumNodeGC(t *testing.T) {
	validCN := &v2.CiliumNode{
		ObjectMeta: metav1.ObjectMeta{
			Name: "valid-node",
		},
	}
	invalidCN := &v2.CiliumNode{
		ObjectMeta: metav1.ObjectMeta{
			Name: "invalid-node",
		},
	}
	invalidCNWithOwnerRef := &v2.CiliumNode{
		ObjectMeta: metav1.ObjectMeta{
			Name: "invalid-node-with-owner-ref",
			OwnerReferences: []metav1.OwnerReference{
				{},
			},
		},
	}

	fcn := fake.NewSimpleClientset(validCN, invalidCN, invalidCNWithOwnerRef).CiliumV2().CiliumNodes()

	fCNStore := &cache.FakeCustomStore{
		ListKeysFunc: func() []string {
			return []string{"valid-node", "invalid-node"}
		},
		GetByKeyFunc: func(key string) (interface{}, bool, error) {
			return &v2.CiliumNode{
				ObjectMeta: metav1.ObjectMeta{
					Name: key,
				},
			}, true, nil
		},
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
	err := performCiliumNodeGC(context.TODO(), fcn, fCNStore, fng, interval, candidateStore)
	assert.NoError(t, err)
	assert.Len(t, candidateStore.nodesToRemove, 1)
	_, exists := candidateStore.nodesToRemove["invalid-node"]
	assert.True(t, exists)

	// check if the invalid node is actually GC-ed
	time.Sleep(interval)
	err = performCiliumNodeGC(context.TODO(), fcn, fCNStore, fng, interval, candidateStore)
	assert.NoError(t, err)
	assert.Len(t, candidateStore.nodesToRemove, 0)
	_, exists = candidateStore.nodesToRemove["invalid-node"]
	assert.False(t, exists)
}
