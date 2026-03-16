// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package externalgroups

import (
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/stretchr/testify/require"

	apiv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/policy/api"
)

func TestOnCCGUpdate(t *testing.T) {
	egm := newEGM(t)

	ccg1v1 := &apiv2.CiliumCIDRGroup{
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
	ccg1v2 := ccg1v1.DeepCopy()
	ccg1v2.ResourceVersion = "2"

	ccg2v1 := &apiv2.CiliumCIDRGroup{
		ObjectMeta: metav1.ObjectMeta{
			Name: namePrefix + "ccg2",
			Labels: map[string]string{
				LabelGroupManaged: "",
				group2.LabelKey(): "",
			},
			ResourceVersion: "1",
		},
		Spec: apiv2.CiliumCIDRGroupSpec{
			ExternalCIDRs: []api.CIDR{"192.0.2.2/32"},
		},
	}
	ccg2v2 := ccg2v1.DeepCopy()
	ccg2v2.ResourceVersion = "2"

	expectRow := func(id, name, rv string, owner Owner) {
		t.Helper()
		name = namePrefix + name
		rtx := egm.db.ReadTxn()
		row, _, _ := egm.tbl.Get(rtx, ExternalGroupByID(id))
		require.NotNil(t, row)
		require.NotNil(t, row.CCG)
		require.Equal(t, name, row.CCGName)
		require.Equal(t, name, row.CCG.Name)
		require.Equal(t, rv, row.CCG.ResourceVersion)

		if owner.Name != "" {
			require.True(t, row.Owners.Has(owner))
		}
	}

	zero := Owner{}

	ctx := t.Context()
	egm.onCCGUpdate(ctx, ccg1v1)
	expectRow(group1id, "ccg1", "1", zero)

	// Learn about group2 first from policy
	egm.SetResourceGroups(gk, owner1.Namespace, owner1.Name, groups2)

	// add ccg2 to the existing row
	egm.onCCGUpdate(ctx, ccg2v1)
	expectRow(group1id, "ccg1", "1", zero)
	expectRow(group2id, "ccg2", "1", owner1)

	// update 1 to v2. Twice.
	egm.onCCGUpdate(ctx, ccg1v2)
	expectRow(group1id, "ccg1", "2", zero)
	expectRow(group2id, "ccg2", "1", owner1)

	egm.onCCGUpdate(ctx, ccg1v2)
	expectRow(group1id, "ccg1", "2", zero)
	expectRow(group2id, "ccg2", "1", owner1)

	// update 2 to v2
	egm.onCCGUpdate(ctx, ccg2v2)
	expectRow(group1id, "ccg1", "2", zero)
	expectRow(group2id, "ccg2", "2", owner1)

	// learn about group1 last from policy
	egm.SetResourceGroups(gk, owner1.Namespace, owner1.Name, groups12)
	expectRow(group1id, "ccg1", "2", owner1)
	expectRow(group2id, "ccg2", "2", owner1)
}
