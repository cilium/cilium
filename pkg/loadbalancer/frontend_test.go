// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package loadbalancer

import (
	"net/netip"
	"testing"

	"github.com/cilium/statedb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLookupFrontendByTuple(t *testing.T) {
	db := statedb.New()
	fes, err := NewFrontendsTable(DefaultConfig, db)
	require.NoError(t, err, "NewFrontendsTable")

	var addr L3n4Addr
	addr.ParseFromString("10.0.0.1:80/TCP")

	wtxn := db.WriteTxn(fes)
	fe := &Frontend{
		FrontendParams: FrontendParams{Address: addr},
	}
	fes.Insert(wtxn, fe)
	txn := wtxn.Commit()

	fe2, found := LookupFrontendByTuple(txn, fes, addr.AddrCluster(), addr.Protocol(), addr.Port(), addr.Scope())
	require.True(t, found)
	require.NotNil(t, fe2)
	require.Equal(t, fe, fe2)

	var addr2 L3n4Addr
	addr2.ParseFromString("10.0.0.2:80/TCP")
	fe2, found = LookupFrontendByTuple(txn, fes, addr2.AddrCluster(), addr2.Protocol(), addr2.Port(), addr2.Scope())
	require.False(t, found)
	require.Nil(t, fe2)
}

func TestGetSourceRangesEnabled(t *testing.T) {
	prefix := netip.MustParsePrefix("10.0.0.0/8")

	tests := []struct {
		name                  string
		sourceRanges          []netip.Prefix
		svcType               SVCType
		lbSourceRangeAllTypes bool
		want                  bool
	}{
		{
			name:         "LoadBalancer with source ranges",
			sourceRanges: []netip.Prefix{prefix},
			svcType:      SVCTypeLoadBalancer,
			want:         true,
		},
		{
			// loadBalancerSourceRanges must also apply to ExternalIPs frontends (#44718).
			name:         "ExternalIPs with source ranges",
			sourceRanges: []netip.Prefix{prefix},
			svcType:      SVCTypeExternalIPs,
			want:         true,
		},
		{
			name:    "ExternalIPs without source ranges",
			svcType: SVCTypeExternalIPs,
			want:    false,
		},
		{
			name:                  "ExternalIPs with source ranges, allTypes=true",
			sourceRanges:          []netip.Prefix{prefix},
			svcType:               SVCTypeExternalIPs,
			lbSourceRangeAllTypes: true,
			want:                  true,
		},
		{
			name:         "NodePort with source ranges, allTypes=false",
			sourceRanges: []netip.Prefix{prefix},
			svcType:      SVCTypeNodePort,
			want:         false,
		},
		{
			name:                  "NodePort with source ranges, allTypes=true",
			sourceRanges:          []netip.Prefix{prefix},
			svcType:               SVCTypeNodePort,
			lbSourceRangeAllTypes: true,
			want:                  true,
		},
		{
			name:    "LoadBalancer without source ranges",
			svcType: SVCTypeLoadBalancer,
			want:    false,
		},
		{
			name:         "ClusterIP with source ranges",
			sourceRanges: []netip.Prefix{prefix},
			svcType:      SVCTypeClusterIP,
			want:         false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fe := &Frontend{SourceRanges: tt.sourceRanges, FrontendParams: FrontendParams{
				Type: tt.svcType,
			}}
			got := fe.GetSourceRangesEnabled(tt.lbSourceRangeAllTypes)
			assert.Equal(t, tt.want, got)
		})
	}
}
