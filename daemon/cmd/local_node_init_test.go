// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8sLabels "k8s.io/apimachinery/pkg/labels"
	k8sRuntime "k8s.io/apimachinery/pkg/runtime"

	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/k8s/resource"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/node/addressing"
	"github.com/cilium/cilium/pkg/node/types"
	"github.com/cilium/cilium/pkg/option"
)

func TestInitLocalNode_initFromK8s(t *testing.T) {
	lni := &localNodeInitializer{
		localNodeInitializerParams: localNodeInitializerParams{
			Config: &option.DaemonConfig{
				IPv4NodeAddr:               "auto",
				IPv6NodeAddr:               "auto",
				NodeEncryptionOptOutLabels: k8sLabels.NewSelector(),
			},
			LocalNode: &mockResource[*slim_corev1.Node]{
				items: []resource.Event[*slim_corev1.Node]{
					{
						Kind: resource.Upsert,
						Object: &slim_corev1.Node{
							ObjectMeta: slim_metav1.ObjectMeta{
								Labels: map[string]string{
									"x": "y",
								},
								Name:      "test-node",
								Namespace: "test-namespace",
							},
						},
						Done: func(err error) {},
					},
				},
			},
			K8sCiliumLocalNode: &mockResource[*v2.CiliumNode]{
				items: []resource.Event[*v2.CiliumNode]{
					{
						Kind: resource.Upsert,
						Object: &v2.CiliumNode{
							ObjectMeta: metav1.ObjectMeta{
								Name:      "test-node",
								Namespace: "test-namespace",
								Labels: map[string]string{
									"x": "y",
								},
							},
							Spec: v2.NodeSpec{
								Addresses: []v2.NodeAddress{
									{
										Type: addressing.NodeCiliumInternalIP,
										IP:   "10.0.0.1",
									},
									{
										Type: addressing.NodeCiliumInternalIP,
										IP:   "fd00:10:244:1::aaa6",
									},
								},
							},
						},
						Done: func(err error) {},
					},
				},
			},
		},
	}
	n := &node.LocalNode{
		Node: types.Node{
			Labels: map[string]string{},
		},
	}
	err := lni.InitLocalNode(context.Background(), n)
	assert.NoError(t, err)
	assert.Equal(t, "10.0.0.1", n.GetCiliumInternalIP(false).String())
	assert.Equal(t, "fd00:10:244:1::aaa6", n.GetCiliumInternalIP(true).String())
	assert.Equal(t, n.Name, "test-node")
}

type mockResource[T k8sRuntime.Object] struct {
	items []resource.Event[T]
}

func (mr *mockResource[T]) Observe(ctx context.Context, next func(resource.Event[T]), complete func(error)) {
	panic("observe not impl")
}

func (mr *mockResource[T]) Events(ctx context.Context, opts ...resource.EventsOpt) <-chan resource.Event[T] {
	ch := make(chan resource.Event[T], len(mr.items))
	for _, item := range mr.items {
		ch <- item
	}
	return ch
}

func (mr *mockResource[T]) Store(context.Context) (resource.Store[T], error) {
	panic("store not impl")
}
