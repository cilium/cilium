// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cache

import (
	"context"
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"

	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/testutils"
)

func TestLookupReservedIdentity(t *testing.T) {
	testutils.IntegrationTest(t)

	for _, testConfig := range testConfigs {
		t.Run(testConfig.name, func(t *testing.T) {
			testLookupReservedIdentity(t, testConfig)
		})
	}
}

func testLookupReservedIdentity(t *testing.T, testConfig testConfig) {
	logger := hivetest.Logger(t)
	mgr := NewCachingIdentityAllocator(logger, newDummyOwner(logger), testConfig.allocatorConfig)
	<-mgr.InitIdentityAllocator(nil)

	hostID := identity.GetReservedID("host")
	require.NotNil(t, mgr.LookupIdentityByID(context.TODO(), hostID))

	id := mgr.LookupIdentity(context.TODO(), labels.NewLabelsFromModel([]string{"reserved:host"}))
	require.NotNil(t, id)
	require.Equal(t, hostID, id.ID)

	worldID := identity.GetReservedID("world")
	require.NotNil(t, mgr.LookupIdentityByID(context.TODO(), worldID))

	id = mgr.LookupIdentity(context.TODO(), labels.NewLabelsFromModel([]string{"reserved:world"}))
	require.NotNil(t, id)
	require.Equal(t, worldID, id.ID)

	identity.InitWellKnownIdentities(fakeConfig, cmtypes.ClusterInfo{Name: "default", ID: 5})
}

func TestLookupReservedIdentityByLabels(t *testing.T) {
	testutils.IntegrationTest(t)

	ni, err := identity.ParseNumericIdentity("129")
	require.NoError(t, err)
	identity.AddUserDefinedNumericIdentity(ni, "kvstore")
	identity.AddReservedIdentity(ni, "kvstore")

	type args struct {
		lbls labels.Labels
	}
	tests := []struct {
		name string
		args args
		want *identity.Identity
	}{
		{
			name: "fixed-identity",
			args: args{
				lbls: labels.Labels{labels.LabelKeyFixedIdentity: labels.ParseLabel(labels.LabelKeyFixedIdentity + "=" + "kvstore")},
			},
			want: identity.NewIdentity(ni, labels.Labels{"kvstore": labels.NewLabel("kvstore", "", labels.LabelSourceReserved)}),
		},
		{
			name: "fixed-identity+reserved-identity returns fixed",
			args: args{
				lbls: labels.Labels{
					labels.LabelKeyFixedIdentity: labels.ParseLabel(labels.LabelKeyFixedIdentity + "=" + "kvstore"),
					labels.IDNameHost:            labels.LabelHost[labels.IDNameHost],
				},
			},
			want: identity.NewIdentity(ni, labels.Labels{"kvstore": labels.NewLabel("kvstore", "", labels.LabelSourceReserved)}),
		},
		{
			name: "reserved-identity+fixed-identity returns fixed",
			args: args{
				lbls: labels.Labels{
					labels.IDNameHost:            labels.LabelHost[labels.IDNameHost],
					labels.LabelKeyFixedIdentity: labels.ParseLabel(labels.LabelKeyFixedIdentity + "=" + "kvstore"),
				},
			},
			want: identity.NewIdentity(ni, labels.Labels{"kvstore": labels.NewLabel("kvstore", "", labels.LabelSourceReserved)}),
		},
		{
			name: "non-existing-fixed-identity",
			args: args{
				lbls: labels.Labels{labels.LabelKeyFixedIdentity: labels.ParseLabel(labels.LabelKeyFixedIdentity + "=" + "kube-dns")},
			},
			want: nil,
		},
		{
			name: "reserved-identity",
			args: args{
				lbls: labels.LabelHost,
			},
			want: identity.NewIdentity(identity.ReservedIdentityHost, labels.LabelHost),
		},
		{
			name: "reserved-identity+other-labels",
			args: args{
				lbls: labels.Labels{
					labels.IDNameHost: labels.LabelHost[labels.IDNameHost],
					"id.foo":          labels.ParseLabel("id.foo"),
				},
			},
			want: identity.NewIdentity(identity.ReservedIdentityHost, labels.Labels{
				labels.IDNameHost: labels.LabelHost[labels.IDNameHost],
				"id.foo":          labels.ParseLabel("id.foo"),
			},
			),
		},
		{
			name: "no fixed and reserved identities returns nil",
			args: args{
				lbls: labels.Labels{
					"id.foo": labels.ParseLabel("id.foo"),
				},
			},
			want: nil,
		},
	}

	for _, tt := range tests {
		got := identity.LookupReservedIdentityByLabels(tt.args.lbls)
		switch {
		case got == nil && tt.want == nil:
		case got == nil && tt.want != nil ||
			got != nil && tt.want == nil ||
			got.ID != tt.want.ID:

			t.Errorf("test %s: LookupReservedIdentityByLabels() = %v, want %v", tt.name, got, tt.want)
		}
	}
}
