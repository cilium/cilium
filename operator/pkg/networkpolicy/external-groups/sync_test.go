// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package externalgroups

import (
	"fmt"
	"net/netip"
	"testing"
	"time"

	"github.com/cilium/statedb/part"
	"github.com/stretchr/testify/require"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	k8sTesting "k8s.io/client-go/testing"

	"github.com/cilium/cilium/operator/pkg/networkpolicy/external-groups/provider"
	apiv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/k8s/client/testutils"
	"github.com/cilium/cilium/pkg/policy/api"
)

func TestToSync(t *testing.T) {
	before := time.Now().Add(-1 * time.Minute)
	soon := time.Now().Add(1 * time.Minute)
	later := time.Now().Add(1 * time.Hour)

	rows := []*ExternalGroup{
		// never synced
		{
			ID:     "id0",
			Owners: part.NewSet(owner1),
		},
		// synced but now no owners
		{
			ID:          "id1",
			CCGName:     "id2",
			CCG:         &apiv2.CiliumCIDRGroup{},
			Owners:      part.NewSet[Owner](),
			NextRefresh: later,
		},
		// CCG was deleted
		{
			ID:          "id2",
			Owners:      part.NewSet(owner1),
			NextRefresh: later,
		},
		// Everything OK, but due for resync
		{
			ID:          "id3",
			Owners:      part.NewSet(owner1),
			CCGName:     "id3",
			CCG:         &apiv2.CiliumCIDRGroup{},
			NextRefresh: before,
		},
		// doesn't need sync
		{
			ID:          "id4",
			CCGName:     "id4",
			CCG:         &apiv2.CiliumCIDRGroup{},
			Owners:      part.NewSet(owner1),
			NextRefresh: later,
		},
		// also doesn't need sync, but next refresh is sooner
		{
			ID:          "id5",
			CCGName:     "id5",
			CCG:         &apiv2.CiliumCIDRGroup{},
			Owners:      part.NewSet(owner1),
			NextRefresh: soon,
		},
	}

	egm := newEGM(t)
	wtxn := egm.db.WriteTxn(egm.tbl)
	for _, row := range rows {
		_, update, err := egm.tbl.Insert(wtxn, row)
		require.NoError(t, err)
		require.False(t, update)
	}
	wtxn.Commit()

	toSync, nextRefresh := egm.groupsToSync()
	expected := []*ExternalGroup{
		rows[0], rows[1], rows[2], rows[3],
	}
	require.Equal(t, expected, toSync)
	require.Equal(t, soon, nextRefresh)
}

func TestEnsureGroup(t *testing.T) {
	provider.RegisterTestDummyProvider()

	egm := newEGM(t)
	fcs, cs := testutils.NewFakeClientset(egm.log)
	egm.clientset = cs

	nameIdx := 0
	rv := 0
	fcs.CiliumFakeClientset.PrependReactor(
		"create", "*",
		func(action k8sTesting.Action) (handled bool, ret runtime.Object, err error) {
			ret = action.(k8sTesting.CreateAction).GetObject()
			meta, ok := ret.(metav1.Object)
			if !ok {
				return
			}

			if meta.GetName() == "" && meta.GetGenerateName() != "" {
				meta.SetName(fmt.Sprintf("%sname-%d", meta.GetGenerateName(), nameIdx))
				t.Log("generated name", meta.GetName())
			}
			meta.SetResourceVersion(fmt.Sprintf("%d", rv))
			rv++
			meta.SetCreationTimestamp(metav1.NewTime(time.Now()))
			nameIdx++

			return
		},
	)

	fcs.CiliumFakeClientset.PrependReactor(
		"update", "*",
		func(action k8sTesting.Action) (handled bool, ret runtime.Object, err error) {
			ret = action.(k8sTesting.UpdateAction).GetObject()
			meta, ok := ret.(metav1.Object)
			if !ok {
				return
			}

			meta.SetResourceVersion(fmt.Sprintf("%d", rv))
			rv++

			return
		},
	)

	// Insert dummy row
	row0 := &ExternalGroup{
		ID:       group1id,
		ExtGroup: group1,
		Owners:   part.NewSet(owner1),
	}

	wtxn := egm.db.WriteTxn(egm.tbl)
	_, _, err := egm.tbl.Insert(wtxn, row0)
	require.NoError(t, err)
	wtxn.Commit()

	ctx := t.Context()

	getRow := func(id string) *ExternalGroup {
		row, _, ok := egm.tbl.Get(egm.db.ReadTxn(), ExternalGroupByID(id))
		require.True(t, ok)
		return row
	}

	t1 := time.Now()

	err = egm.ensureGroup(ctx, row0)
	require.NoError(t, err)

	row1 := getRow(group1id)
	require.NotNil(t, row1.CCG)
	require.NotEmpty(t, row1.CCGName)
	require.True(t, row1.NextRefresh.After(t1))
	require.EqualValues(t, "192.0.2.1/32", row1.CCG.Spec.ExternalCIDRs[0])

	// Update CIDRs
	t2 := time.Now()
	provider.DummmyIP1 = netip.MustParseAddr("192.0.2.3")
	err = egm.ensureGroup(ctx, row1)
	require.NoError(t, err)

	row2 := getRow(group1id)
	require.NotNil(t, row2.CCG)
	require.NotEmpty(t, row2.CCGName)
	require.True(t, row2.NextRefresh.After(t2))
	require.EqualValues(t, "192.0.2.3/32", row2.CCG.Spec.ExternalCIDRs[0])
	require.NotEqual(t, row1.CCG.ResourceVersion, row2.CCG.ResourceVersion)

	// Refresh (without changing CIDRs)
	// Refresh time should be bumped, but the underlying CCG should have the same resource version
	err = egm.ensureGroup(ctx, row2)
	require.NoError(t, err)
	row3 := getRow(group1id)
	require.NotNil(t, row2.CCG)
	require.NotEmpty(t, row2.CCGName)
	require.NotEqual(t, row2.NextRefresh, row3.NextRefresh)
	require.Equal(t, row2.CCG.ResourceVersion, row3.CCG.ResourceVersion)
}

func TestRemoveGroup(t *testing.T) {
	ctx := t.Context()

	egm := newEGM(t)
	_, cs := testutils.NewFakeClientset(egm.log)
	egm.clientset = cs

	ccg0 := &apiv2.CiliumCIDRGroup{
		ObjectMeta: metav1.ObjectMeta{
			Name: namePrefix + "ccg1",
			Labels: map[string]string{
				LabelGroupManaged: "",
				group1.LabelKey(): "",
			},
			ResourceVersion: "1",
		},
		Spec: apiv2.CiliumCIDRGroupSpec{
			ExternalCIDRs: []api.CIDR{"192.0.2.1/32"},
		},
	}

	egm.createCCG(ctx, ccg0)

	// create CCG in apiserver
	ccg1, err := cs.CiliumV2().CiliumCIDRGroups().Get(ctx, ccg0.Name, metav1.GetOptions{})
	require.NoError(t, err)
	require.Equal(t, ccg0.Spec, ccg1.Spec)

	row0 := &ExternalGroup{
		ID:       group1id,
		ExtGroup: group1,
		Owners:   part.NewSet(owner1),
		CCG:      ccg1,
		CCGName:  ccg1.Name,
	}

	wtxn := egm.db.WriteTxn(egm.tbl)
	_, _, err = egm.tbl.Insert(wtxn, row0)
	require.NoError(t, err)
	wtxn.Commit()

	// Test that groups are not removed when they have owners
	err = egm.removeGroup(ctx, row0)
	require.NoError(t, err)

	ccg2, err := cs.CiliumV2().CiliumCIDRGroups().Get(ctx, ccg1.Name, metav1.GetOptions{})
	require.NoError(t, err)
	require.NotNil(t, ccg2)

	// set to 0 owners
	row1 := row0.ShallowCopy()
	row1.Owners = row1.Owners.Delete(owner1)
	wtxn = egm.db.WriteTxn(egm.tbl)
	_, _, err = egm.tbl.Insert(wtxn, row1)
	require.NoError(t, err)
	wtxn.Commit()

	// this should remove the group from the apiserver
	err = egm.removeGroup(ctx, row1)
	require.NoError(t, err)

	// check ccg is gone
	_, err = cs.CiliumV2().CiliumCIDRGroups().Get(ctx, ccg1.Name, metav1.GetOptions{})
	require.True(t, apierrors.IsNotFound(err))

	// check db row is gone
	_, _, found := egm.tbl.Get(egm.db.ReadTxn(), ExternalGroupByID(group1id))
	require.False(t, found)

}
