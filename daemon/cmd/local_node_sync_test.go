// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/labels"
	k8stypes "k8s.io/apimachinery/pkg/types"

	"github.com/cilium/cilium/pkg/k8s/resource"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/node/types"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/stream"
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
				NodeEncryptionOptOutLabels: labels.Nothing(),
			},
			K8sLocalNode: fln,
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
