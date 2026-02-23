// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package sync

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/cilium/hive/hivetest"
	"github.com/cilium/stream"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8sRuntime "k8s.io/apimachinery/pkg/runtime"
	k8stypes "k8s.io/apimachinery/pkg/types"

	fakeTypes "github.com/cilium/cilium/pkg/datapath/fake/types"
	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/k8s/resource"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/node/addressing"
	"github.com/cilium/cilium/pkg/node/types"
	"github.com/cilium/cilium/pkg/option"
)

// Mock resources for testing
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
	// Keep channel open until context is cancelled to simulate blocking behavior
	go func() {
		<-ctx.Done()
		close(ch)
	}()
	return ch
}

func (mr *mockResource[T]) Store(context.Context) (resource.Store[T], error) {
	panic("store not impl")
}

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
		local = node.LocalNode{
			Node: types.Node{
				Labels:      map[string]string{"ex": "label"},
				Annotations: map[string]string{"ex": "annot"},
			},
			Local: &node.LocalNodeInfo{},
		}
		fln  = newFakeLocalNode()
		sync = newLocalNodeSynchronizer(localNodeSynchronizerParams{
			Logger: hivetest.Logger(t),
			Config: &option.DaemonConfig{
				IPv4NodeAddr: "1.2.3.4",
				IPv6NodeAddr: "fd00::1",
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
			IPsecConfig: fakeTypes.IPsecConfig{},
		})
	)

	require.NoError(t, sync.InitLocalNode(t.Context(), &local))
	require.EqualValues(t, 1, fln.done)
	require.Equal(t, "foo", local.Name)
	require.Equal(t, "10.0.0.1", local.GetNodeInternalIPv4().String())
	require.Equal(t, "fc00::11", local.GetNodeInternalIPv6().String())
	require.Equal(t, map[string]string{"ex": "label", "foo": "bar"}, local.Labels)
	require.Equal(t, map[string]string{"ex": "annot", "cilium.io/baz": "qux"}, local.Annotations)
	require.Equal(t, k8stypes.UID("uid1"), local.Local.UID)
	require.Equal(t, "provider://foobar", local.Local.ProviderID)

	store := node.NewTestLocalNodeStore(local)

	sync.SyncLocalNode(t.Context(), store)

	// Assert that SyncLocalNode processed all the events emitted by [fln]
	require.EqualValues(t, 5, fln.done)

	// The observed update at this point will be the final state.
	updates := stream.ToChannel(t.Context(), store)
	update := <-updates
	require.Equal(t, map[string]string{"ex": "label", "qux": "baz"}, update.Labels)
	require.Equal(t, map[string]string{"ex": "annot", "cilium.io/bar": "foo"}, update.Annotations)
	require.Equal(t, k8stypes.UID("uid2"), update.Local.UID)
	require.Equal(t, "provider://foobaz", update.Local.ProviderID)

	n, err := store.Get(t.Context())
	require.NoError(t, err)
	require.True(t, n.DeepEqual(&update))
}

func TestInitLocalNode_initFromK8s(t *testing.T) {
	lni := newLocalNodeSynchronizer(
		localNodeSynchronizerParams{
			Logger: hivetest.Logger(t),
			Config: &option.DaemonConfig{
				IPv4NodeAddr:                 "auto",
				IPv6NodeAddr:                 "auto",
				IPv6ClusterAllocCIDRBase:     "fd00::",
				EnableIPv4:                   true,
				EnableIPv6:                   true,
				EnableHealthChecking:         true,
				EnableEndpointHealthChecking: true,
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
			IPsecConfig: fakeTypes.IPsecConfig{},
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
	)
	n := &node.LocalNode{
		Node: types.Node{
			Labels: map[string]string{},
		},
		Local: &node.LocalNodeInfo{},
	}
	err := lni.InitLocalNode(context.Background(), n)
	assert.NoError(t, err)
	assert.Equal(t, "10.0.0.1", n.GetCiliumInternalIP(false).String())
	assert.Equal(t, "fd00:10:244:1::aaa6", n.GetCiliumInternalIP(true).String())
	assert.Equal(t, "10.0.0.2", n.IPv4HealthIP.String())
	assert.Equal(t, "fd00:10:244:1::aaa7", n.IPv6HealthIP.String())
	assert.Equal(t, "test-node", n.Name)
}

func TestLocalNodeSync_NodeDeletion(t *testing.T) {
	// Helper to create test node object
	createTestNode := func(deletionTimestamp *slim_metav1.Time) *slim_corev1.Node {
		return &slim_corev1.Node{
			ObjectMeta: slim_metav1.ObjectMeta{
				Name:              "test-node",
				UID:               k8stypes.UID("test-uid"),
				DeletionTimestamp: deletionTimestamp,
			},
			Status: slim_corev1.NodeStatus{
				Addresses: []slim_corev1.NodeAddress{
					{Type: slim_corev1.NodeInternalIP, Address: "10.0.0.1"},
				},
			},
		}
	}

	t.Run("upsert_with_deletion_timestamp", func(t *testing.T) {
		now := slim_metav1.Now()
		nodeEvent := resource.Event[*slim_corev1.Node]{
			Kind:   resource.Upsert,
			Key:    resource.Key{Name: "test-node"},
			Object: createTestNode(&now),
			Done:   func(err error) {},
		}
		testNodeDeletion(t, nodeEvent)
	})

	t.Run("delete_event", func(t *testing.T) {
		nodeEvent := resource.Event[*slim_corev1.Node]{
			Kind:   resource.Delete,
			Key:    resource.Key{Name: "test-node"},
			Object: createTestNode(nil),
			Done:   func(err error) {},
		}
		testNodeDeletion(t, nodeEvent)
	})
}

func testNodeDeletion(t *testing.T, nodeEvent resource.Event[*slim_corev1.Node]) {
	t.Helper()

	// Helper to create test node object
	createTestNode := func(deletionTimestamp *slim_metav1.Time) *slim_corev1.Node {
		return &slim_corev1.Node{
			ObjectMeta: slim_metav1.ObjectMeta{
				Name:              "test-node",
				UID:               k8stypes.UID("test-uid"),
				DeletionTimestamp: deletionTimestamp,
			},
			Status: slim_corev1.NodeStatus{
				Addresses: []slim_corev1.NodeAddress{
					{Type: slim_corev1.NodeInternalIP, Address: "10.0.0.1"},
				},
			},
		}
	}

	// Create a normal node event first
	normalEvent := resource.Event[*slim_corev1.Node]{
		Kind:   resource.Upsert,
		Key:    resource.Key{Name: "test-node"},
		Object: createTestNode(nil),
		Done:   func(err error) {},
	}

	fakeNode := &mockResource[*slim_corev1.Node]{
		items: []resource.Event[*slim_corev1.Node]{normalEvent, nodeEvent},
	}

	sync := newLocalNodeSynchronizer(localNodeSynchronizerParams{
		Logger: hivetest.Logger(t),
		Config: &option.DaemonConfig{
			IPv4NodeAddr: "1.2.3.4",
			IPv6NodeAddr: "fd00::1",
		},
		IPsecConfig:  fakeTypes.IPsecConfig{},
		K8sLocalNode: fakeNode,
		K8sCiliumLocalNode: &mockResource[*v2.CiliumNode]{
			items: []resource.Event[*v2.CiliumNode]{
				{Kind: resource.Sync, Done: func(err error) {}},
			},
		},
	})

	// Initialize local node
	local := node.LocalNode{Node: types.Node{Name: "test-node"}, Local: &node.LocalNodeInfo{}}
	store := node.NewTestLocalNodeStore(local)

	// Start observing updates
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	updates := stream.ToChannel(ctx, store, stream.WithBufferSize(3))

	// Verify initial state
	initialNode, _ := store.Get(context.Background())
	assert.False(t, initialNode.Local.IsBeingDeleted)

	// Start the sync
	go sync.SyncLocalNode(ctx, store)

	// Wait for the deletion update - may come after the normal update
	var foundDeleted bool
	for !foundDeleted {
		select {
		case updatedNode := <-updates:
			if updatedNode.Local.IsBeingDeleted {
				foundDeleted = true
			}
		case <-ctx.Done():
			t.Fatal("Timeout waiting for node update")
		}
	}
	assert.True(t, foundDeleted, "Node should be marked as being deleted")
}
