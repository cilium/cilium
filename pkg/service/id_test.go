// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package service

import (
	"testing"

	"github.com/stretchr/testify/require"

	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/loadbalancer"
)

var (
	l3n4Addr1 = loadbalancer.L3n4Addr{
		AddrCluster: cmtypes.MustParseAddrCluster("::1"),
		L4Addr:      loadbalancer.L4Addr{Port: 0, Protocol: "UDP"},
	}
	l3n4Addr2 = loadbalancer.L3n4Addr{
		AddrCluster: cmtypes.MustParseAddrCluster("::1"),
		L4Addr:      loadbalancer.L4Addr{Port: 1, Protocol: "TCP"},
	}
	l3n4Addr3 = loadbalancer.L3n4Addr{
		AddrCluster: cmtypes.MustParseAddrCluster("::1"),
		L4Addr:      loadbalancer.L4Addr{Port: 1, Protocol: "UDP"},
	}
	l3n4Addr4 = loadbalancer.L3n4Addr{
		AddrCluster: cmtypes.MustParseAddrCluster("::1"),
		L4Addr:      loadbalancer.L4Addr{Port: 2, Protocol: "UDP"},
	}
	l3n4Addr5 = loadbalancer.L3n4Addr{
		AddrCluster: cmtypes.MustParseAddrCluster("::2"),
		L4Addr:      loadbalancer.L4Addr{Port: 2, Protocol: "UDP"},
	}
	l3n4Addr6 = loadbalancer.L3n4Addr{
		AddrCluster: cmtypes.MustParseAddrCluster("::3"),
		L4Addr:      loadbalancer.L4Addr{Port: 2, Protocol: "UDP"},
	}
	wantL3n4AddrID = &loadbalancer.L3n4AddrID{
		ID:       123,
		L3n4Addr: l3n4Addr2,
	}
)

func TestServices(t *testing.T) {
	var nilL3n4AddrID *loadbalancer.L3n4AddrID
	// Set up last free ID with zero
	id, err := getMaxServiceID()
	require.Equal(t, nil, err)
	require.Equal(t, FirstFreeServiceID, id)

	ffsIDu16 := loadbalancer.ServiceID(uint16(FirstFreeServiceID))

	l3n4AddrID, err := AcquireID(l3n4Addr1, 0)
	require.Equal(t, nil, err)
	require.Equal(t, loadbalancer.ID(ffsIDu16), l3n4AddrID.ID)

	l3n4AddrID, err = AcquireID(l3n4Addr1, 0)
	require.Equal(t, nil, err)
	require.Equal(t, loadbalancer.ID(ffsIDu16), l3n4AddrID.ID)

	l3n4AddrID, err = AcquireID(l3n4Addr2, 0)
	require.Equal(t, nil, err)
	require.Equal(t, loadbalancer.ID(ffsIDu16+1), l3n4AddrID.ID)

	l3n4AddrID, err = AcquireID(l3n4Addr3, 0)
	require.Equal(t, nil, err)
	require.Equal(t, loadbalancer.ID(ffsIDu16+2), l3n4AddrID.ID)

	gotL3n4AddrID, err := GetID(FirstFreeServiceID)
	require.Equal(t, nil, err)
	wantL3n4AddrID.ID = loadbalancer.ID(ffsIDu16)
	wantL3n4AddrID.L3n4Addr = l3n4Addr1
	require.EqualValues(t, wantL3n4AddrID, gotL3n4AddrID)

	err = DeleteID(FirstFreeServiceID)
	require.Equal(t, nil, err)
	gotL3n4AddrID, err = GetID(FirstFreeServiceID)
	require.Equal(t, nil, err)
	require.Equal(t, nilL3n4AddrID, gotL3n4AddrID)

	gotL3n4AddrID, err = GetID(FirstFreeServiceID + 1)
	require.Equal(t, nil, err)
	wantL3n4AddrID.ID = loadbalancer.ID(FirstFreeServiceID + 1)
	wantL3n4AddrID.L3n4Addr = l3n4Addr2
	require.EqualValues(t, wantL3n4AddrID, gotL3n4AddrID)

	err = DeleteID(FirstFreeServiceID)
	require.Equal(t, nil, err)

	err = setIDSpace(FirstFreeServiceID, FirstFreeServiceID)
	require.Equal(t, nil, err)

	err = DeleteID(FirstFreeServiceID)
	require.Equal(t, nil, err)
	gotL3n4AddrID, err = GetID(FirstFreeServiceID)
	require.Equal(t, nil, err)
	require.Equal(t, nilL3n4AddrID, gotL3n4AddrID)

	gotL3n4AddrID, err = AcquireID(l3n4Addr2, 0)
	require.Equal(t, nil, err)
	require.Equal(t, loadbalancer.ID(FirstFreeServiceID+1), gotL3n4AddrID.ID)

	err = DeleteID(uint32(gotL3n4AddrID.ID))
	require.Equal(t, nil, err)
	err = DeleteID(FirstFreeServiceID + 1)
	require.Equal(t, nil, err)
	err = DeleteID(FirstFreeServiceID + 1)
	require.Equal(t, nil, err)

	gotL3n4AddrID, err = AcquireID(l3n4Addr2, 0)
	require.Equal(t, nil, err)
	require.Equal(t, loadbalancer.ID(ffsIDu16), gotL3n4AddrID.ID)

	gotL3n4AddrID, err = AcquireID(l3n4Addr1, 0)
	require.Equal(t, nil, err)
	require.Equal(t, loadbalancer.ID(FirstFreeServiceID+1), gotL3n4AddrID.ID)

	gotL3n4AddrID, err = AcquireID(l3n4Addr1, 99)
	require.Equal(t, nil, err)
	require.Equal(t, loadbalancer.ID(FirstFreeServiceID+1), gotL3n4AddrID.ID)

	err = DeleteID(uint32(FirstFreeServiceID + 1))
	require.Equal(t, nil, err)

	gotL3n4AddrID, err = AcquireID(l3n4Addr1, 99)
	require.Equal(t, nil, err)
	require.Equal(t, loadbalancer.ID(99), gotL3n4AddrID.ID)

	// ID "99" has been already allocated to l3n4Addr1
	gotL3n4AddrID, err = AcquireID(l3n4Addr4, 99)
	require.Error(t, err)
	require.Nil(t, gotL3n4AddrID)
}

func TestGetMaxServiceID(t *testing.T) {
	lastID := uint32(MaxSetOfServiceID - 1)

	err := setIDSpace(lastID, MaxSetOfServiceID)
	require.Nil(t, err)

	id, err := getMaxServiceID()
	require.Equal(t, nil, err)
	require.Equal(t, (MaxSetOfServiceID - 1), id)
}

func TestBackendID(t *testing.T) {
	firstBackendID := loadbalancer.BackendID(FirstFreeBackendID)

	id1, err := AcquireBackendID(l3n4Addr1)
	require.Equal(t, nil, err)
	require.Equal(t, firstBackendID, id1)

	id1, err = AcquireBackendID(l3n4Addr1)
	require.Equal(t, nil, err)
	require.Equal(t, firstBackendID, id1)

	id2, err := AcquireBackendID(l3n4Addr2)
	require.Equal(t, nil, err)
	require.Equal(t, firstBackendID+1, id2)

	existingID1, err := LookupBackendID(l3n4Addr1)
	require.Equal(t, nil, err)
	require.Equal(t, id1, existingID1)

	// Check that the backend ID restoration advances the nextID
	err = RestoreBackendID(l3n4Addr5, firstBackendID+10)
	require.Equal(t, nil, err)
	id3, err := AcquireBackendID(l3n4Addr6)
	require.Equal(t, nil, err)
	require.Equal(t, firstBackendID+11, id3)

}

func BenchmarkAllocation(b *testing.B) {
	addr := loadbalancer.L3n4Addr{
		AddrCluster: cmtypes.MustParseAddrCluster("::1"),
		L4Addr:      loadbalancer.L4Addr{Port: 0, Protocol: "UDP"},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		addr.L4Addr.Port = uint16(b.N)
		_, err := AcquireID(addr, 0)
		require.Nil(b, err)
	}
	b.StopTimer()

}
