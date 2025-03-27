// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cache

import (
	"context"
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/kvstore"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/testutils"
)

func TestNoopAllocateIdentity(t *testing.T) {
	testutils.IntegrationTest(t)
	kvstore.SetupDummy(t, "etcd")

	// Init labels are always assigned with NoopAllocator.
	initID := identity.LookupReservedIdentity(identity.ReservedIdentityInit)

	lbls1 := labels.NewLabelsFromSortedList("blah=%%//!!;id=foo;user=anna")
	lbls2 := labels.NewLabelsFromSortedList("id=bar;user=anna")
	lbls3 := labels.NewLabelsFromSortedList("id=bar;user=susan")

	mgr := NewNoopIdentityAllocator(hivetest.Logger(t))
	<-mgr.InitIdentityAllocator(nil)
	defer mgr.Close()

	// Noop AllocateIdentity always returns id=init, isNew=false, error=nil,
	// regardless of the provided labels.
	id1a, isNew, err := mgr.AllocateIdentity(context.Background(), lbls1, false, identity.InvalidIdentity)
	require.NotNil(t, id1a)
	require.NoError(t, err)
	require.False(t, isNew)
	require.Equal(t, initID.LabelArray, id1a.LabelArray)

	id1b, isNew, err := mgr.AllocateIdentity(context.Background(), lbls1, false, identity.InvalidIdentity)
	require.NotNil(t, id1b)
	require.NoError(t, err)
	require.False(t, isNew)
	require.Equal(t, initID.LabelArray, id1b.LabelArray)

	id2, isNew, err := mgr.AllocateIdentity(context.Background(), lbls2, false, identity.InvalidIdentity)
	require.NotNil(t, id2)
	require.NoError(t, err)
	require.False(t, isNew)
	require.Equal(t, initID.LabelArray, id2.LabelArray)

	id3, isNew, err := mgr.AllocateIdentity(context.Background(), lbls3, false, identity.InvalidIdentity)
	require.NotNil(t, id3)
	require.NoError(t, err)
	require.False(t, isNew)
	require.Equal(t, initID.LabelArray, id3.LabelArray)

	reservedID := identity.LookupReservedIdentity(identity.ReservedIdentityHost)
	id4, isNew, err := mgr.AllocateIdentity(context.Background(), reservedID.Labels, false, identity.InvalidIdentity)
	require.NotNil(t, id4)
	require.NoError(t, err)
	require.False(t, isNew)
	require.Equal(t, initID.LabelArray, id4.LabelArray)
}
