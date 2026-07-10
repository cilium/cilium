// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package externalgroups

import (
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/cilium/statedb"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/sets"

	"github.com/cilium/cilium/pkg/policy/api"
)

// some test variables
var (
	owner1 = Owner{
		Group:     "example.com",
		Kind:      "policy",
		Namespace: "testns",
		Name:      "owner1",
	}
	owner2 = Owner{
		Group:     "example.com",
		Kind:      "policy",
		Namespace: "testns",
		Name:      "owner2",
	}
	gk = schema.GroupKind{Group: owner1.Group, Kind: owner1.Kind}

	group1   = &api.Groups{AWS: &api.AWSGroup{SecurityGroupsNames: []string{"dummy1"}}}
	groups1  = []*api.Groups{group1}
	group1id = group1.Hash()

	group2   = &api.Groups{AWS: &api.AWSGroup{SecurityGroupsNames: []string{"dummy2"}}}
	groups2  = []*api.Groups{group2}
	group2id = group2.Hash()
	groups12 = []*api.Groups{group1, group2}
)

func newEGM(t *testing.T) *externalGroupManager {
	params := ExternalGroupManagerParams{
		Cfg: defaultExtGroupConfig,
		Log: hivetest.Logger(t),
		DB:  statedb.New(),
	}
	var err error
	params.EGTable, err = NewExternalGroupTable(params.DB)
	if err != nil {
		t.Error(err)
	}

	return newGroupManager(params)
}

func TestSetResourceGroups(t *testing.T) {
	egm := newEGM(t)

	checkGroups := func(owner Owner, groups []*api.Groups) {
		t.Helper()

		wantIDs := sets.Set[string]{}
		for _, group := range groups {
			wantIDs.Insert(group.Hash())
		}

		haveIDs := sets.Set[string]{}

		rtx := egm.db.ReadTxn()
		for group := range egm.tbl.All(rtx) {
			if group.Owners.Has(owner) {
				haveIDs.Insert(group.ID)
			}
		}

		require.Equal(t, wantIDs, haveIDs, "Owner %s did not have the correct set of groups", owner)
	}

	var last1, last2 []*api.Groups

	check := func() {
		checkGroups(owner1, last1)
		checkGroups(owner2, last2)
	}

	set1 := func(g []*api.Groups) {
		last1 = g
		egm.SetResourceGroups(gk, owner1.Namespace, owner1.Name, g)
		check()
	}
	set2 := func(g []*api.Groups) {
		last2 = g
		egm.SetResourceGroups(gk, owner2.Namespace, owner2.Name, g)
		check()
	}

	set1(groups1)
	set2(groups2)
	set1(groups12)
	set1(nil)
	require.Contains(t, egm.emptyResources, owner1)
	set1(nil)
	require.Contains(t, egm.emptyResources, owner1)
	set2(groups1)
	set1(groups12)
	require.NotContains(t, egm.emptyResources, owner1)
	set2(nil)
	set1(nil)
	set1(groups12)
	set2(groups12)
}
