// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package groups

import (
	"testing"
	"time"

	"github.com/cilium/hive/hivetest"
	"github.com/cilium/hive/job"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/sets"

	"github.com/cilium/cilium/pkg/policy/api"
)

var group1 = &api.Groups{AWS: &api.AWSGroup{Region: "foo=bar"}}
var group1key = groupKey(group1.Hash())
var groups1 = []*api.Groups{group1}

var group2 = &api.Groups{AWS: &api.AWSGroup{Region: "foo=baz"}}
var group2key = groupKey(group2.Hash())
var groups2 = []*api.Groups{group2}
var groups12 = []*api.Groups{group1, group2}

func TestSetResourceGroups(t *testing.T) {

	gc := &externalGroupController{
		log: hivetest.Logger(t),

		pendingResources: sets.Set[schema.GroupKind]{},
		ready:            make(chan struct{}),

		groups:      map[groupKey]*api.Groups{},
		groupOwners: map[groupKey]sets.Set[owner]{},
		owners:      sets.Set[owner]{},
		toUpdate:    sets.Set[groupKey]{},
		nextRefresh: map[groupKey]time.Time{},

		triggerSync: job.NewTrigger(),
	}

	ns := "ns"
	name := "name"
	own := owner{
		gk:        gkCNP,
		namespace: ns,
		name:      name,
	}

	requireOwnsGroup := func(k groupKey) {
		t.Helper()

		require.Contains(t, gc.groupOwners, k)
		require.Contains(t, gc.groupOwners[k], own)
		require.Contains(t, gc.owners, own)
	}

	// set 1 group, ensure it is enqueued
	gc.SetResourceGroups(gkCNP, ns, name, groups1)

	require.Equal(t, group1, gc.groups[group1key])
	requireOwnsGroup(group1key)
	require.Contains(t, gc.toUpdate, group1key)

	// pretend we updated group1
	gc.toUpdate.Clear()

	// Idempotent update: still have just group1
	gc.SetResourceGroups(gkCNP, ns, name, groups1)

	require.Equal(t, group1, gc.groups[group1key])
	requireOwnsGroup(group1key)
	// Not scheduled for update
	require.NotContains(t, gc.toUpdate, group1key)

	// Set groups to 1 and 2
	gc.SetResourceGroups(gkCNP, ns, name, groups12)
	require.Equal(t, group1, gc.groups[group1key])
	require.Equal(t, group2, gc.groups[group2key])
	requireOwnsGroup(group1key)
	requireOwnsGroup(group2key)

	require.NotContains(t, gc.toUpdate, group1key)
	require.Contains(t, gc.toUpdate, group2key)

	gc.toUpdate.Clear()

	// Set groups to 2
	gc.SetResourceGroups(gkCNP, ns, name, groups2)
	require.NotContains(t, gc.groups, group1key)
	require.Equal(t, group2, gc.groups[group2key])
	require.NotContains(t, gc.groupOwners, group1key)
	requireOwnsGroup(group2key)

	require.Contains(t, gc.toUpdate, group1key)
	require.NotContains(t, gc.toUpdate, group2key)

	gc.toUpdate.Clear()

	// Set no groups
	gc.SetResourceGroups(gkCNP, ns, name, nil)
	require.Empty(t, gc.groups)
	require.Empty(t, gc.groupOwners)
	require.Empty(t, gc.owners)

	require.Contains(t, gc.toUpdate, group2key)
}
