// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"context"
	"errors"
	"testing"

	"github.com/cilium/stream"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8sLabels "k8s.io/apimachinery/pkg/labels"
	k8sRuntime "k8s.io/apimachinery/pkg/runtime"
	k8stypes "k8s.io/apimachinery/pkg/types"

	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/k8s/resource"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/node/addressing"
	"github.com/cilium/cilium/pkg/node/types"
	"github.com/cilium/cilium/pkg/option"
)

type fakeLocalNode struct {
	events chan resource.Event[*slim_corev1.Node]
	done   uint8
}

func newFakeLocalNode() *fakeLocalNode {
	var fake fakeLocalNode

	event := func(uid, provider string, labels, annotations map[string]string) resource.Event[*slim_corev1.Node] {
		return resource.Event[*slim_corev1.Node]{
			Kind: resource.Upsert,
			Key:  resource.Key{Name: "foo"},
			Object: &slim_corev1.Node{
				ObjectMeta: slim_metav1.ObjectMeta{Name: "foo", UID: k8stypes.UID(uid), Labels: labels, Annotations: annotations},
				Spec:       slim_corev1.NodeSpec{ProviderID: provider},
				Status: slim_corev1.NodeStatus{Addresses: []slim_corev1.NodeAddress{
					{Type: slim_corev1.NodeInternalIP, Address: "10.0.0.1"},
					{Type: slim_corev1.NodeInternalIP, Address: "fc00::11"},
				}},
			},
			Done: func(err error) { fake.done++ },
		}
	}

	fake.events = make(chan resource.Event[*slim_corev1.Node], 5)
	fake.events <- event("uid1", "provider://foobar", map[string]string{"foo": "bar"}, map[string]string{"cilium.io/baz": "qux"})
	fake.events <- event("uid1", "provider://foobar", map[string]string{"foo": "bar", "qux": "baz"},
		map[string]string{"cilium.io/baz": "qux", "cilium.io/bar": "foo"})
	// Same object, should not cause a LocalNode event to be emitted.
	fake.events <- event("uid1", "provider://foobar", map[string]string{"foo": "bar", "qux": "baz"},
		map[string]string{"cilium.io/baz": "qux", "cilium.io/bar": "foo"})
	fake.events <- event("uid1", "provider://foobar", map[string]string{"qux": "baz"}, map[string]string{"cilium.io/bar": "foo"})
	fake.events <- event("uid2", "provider://foobaz", map[string]string{"qux": "baz"}, map[string]string{"cilium.io/bar": "foo"})
	close(fake.events)

	return &fake
}

func (fln *fakeLocalNode) Observe(context.Context, func(resource.Event[*slim_corev1.Node]), func(error)) {
}

func (fln *fakeLocalNode) Events(context.Context, ...resource.EventsOpt) <-chan resource.Event[*slim_corev1.Node] {
	return fln.events
}

func (fln *fakeLocalNode) Store(context.Context) (resource.Store[*slim_corev1.Node], error) {
	return nil, errors.New("unimplemented")
}

func TestLocalNodeSync(t *testing.T) {
	var (
		local = node.LocalNode{Node: types.Node{
			Labels:      map[string]string{"ex": "label"},
			Annotations: map[string]string{"ex": "annot"},
		}}
		fln  = newFakeLocalNode()
		sync = newLocalNodeSynchronizer(localNodeSynchronizerParams{
			Config: &option.DaemonConfig{
				IPv4NodeAddr:               "1.2.3.4",
				IPv6NodeAddr:               "fd00::1",
				NodeEncryptionOptOutLabels: k8sLabels.Nothing(),
			},
			K8sLocalNode: fln,
			K8sCiliumLocalNode: &mockResource[*v2.CiliumNode]{
				items: []resource.Event[*v2.CiliumNode]{
					{
						Kind: resource.Sync,
						Done: func(err error) {},
					},
				},
			},
		})
	)

	require.NoError(t, sync.InitLocalNode(context.TODO(), &local))
	require.EqualValues(t, 1, fln.done)
	require.Equal(t, "foo", local.Name)
	require.Equal(t, "10.0.0.1", local.GetNodeInternalIPv4().String())
	require.Equal(t, "fc00::11", local.GetNodeInternalIPv6().String())
	require.Equal(t, map[string]string{"ex": "label", "foo": "bar"}, local.Labels)
	require.Equal(t, map[string]string{"ex": "annot", "cilium.io/baz": "qux"}, local.Annotations)
	require.Equal(t, k8stypes.UID("uid1"), local.UID)
	require.Equal(t, "provider://foobar", local.ProviderID)

	store := node.NewTestLocalNodeStore(local)
	updates := stream.ToChannel(context.Background(), store.Observable, stream.WithBufferSize(4))

	sync.SyncLocalNode(context.Background(), store)
	require.EqualValues(t, 5, fln.done)

	update := <-updates
	require.Equal(t, map[string]string{"ex": "label", "foo": "bar"}, update.Labels)
	require.Equal(t, map[string]string{"ex": "annot", "cilium.io/baz": "qux"}, update.Annotations)
	update = <-updates
	require.Equal(t, map[string]string{"ex": "label", "foo": "bar", "qux": "baz"}, update.Labels)
	require.Equal(t, map[string]string{"ex": "annot", "cilium.io/baz": "qux", "cilium.io/bar": "foo"}, update.Annotations)
	update = <-updates
	require.Equal(t, map[string]string{"ex": "label", "qux": "baz"}, update.Labels)
	require.Equal(t, map[string]string{"ex": "annot", "cilium.io/bar": "foo"}, update.Annotations)
	update = <-updates
	require.Equal(t, k8stypes.UID("uid2"), update.UID)
	require.Equal(t, "provider://foobaz", update.ProviderID)
}
func TestInitLocalNode_initFromK8s(t *testing.T) {
	lni := &localNodeSynchronizer{
		localNodeSynchronizerParams: localNodeSynchronizerParams{
			Config: &option.DaemonConfig{
				IPv4NodeAddr:                 "auto",
				IPv6NodeAddr:                 "auto",
				IPv6ClusterAllocCIDRBase:     "fd00::",
				EnableIPv4:                   true,
				EnableIPv6:                   true,
				EnableHealthChecking:         true,
				EnableEndpointHealthChecking: true,
				NodeEncryptionOptOutLabels:   k8sLabels.NewSelector(),
			},
			K8sLocalNode: &mockResource[*slim_corev1.Node]{
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
								HealthAddressing: v2.HealthAddressingSpec{
									IPv4: "10.0.0.2",
									IPv6: "fd00:10:244:1::aaa7",
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
	assert.Equal(t, "10.0.0.2", n.IPv4HealthIP.String())
	assert.Equal(t, "fd00:10:244:1::aaa7", n.IPv6HealthIP.String())
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
