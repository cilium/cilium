// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package loadbalancer

import (
	"bytes"
	"iter"
	"testing"

	"github.com/cilium/statedb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
)

func TestBackendKey(t *testing.T) {
	name := NewServiceNameInCluster("foo", "bar", "baz")
	addr := cmtypes.MustParseAddrCluster("1.2.3.4")
	backendAddr := NewL3n4Addr(TCP, addr, 8080, ScopeExternal)

	key := BackendKey{
		ServiceName:    name,
		Address:        backendAddr,
		SourcePriority: 0,
	}

	keyBytes := key.Key()
	assert.True(t, bytes.HasPrefix(keyBytes, name.Key()), "BackendKey should have ServiceName key as prefix")

	sepIndex := len(name.Key())
	assert.Equal(t, byte(0x00), keyBytes[sepIndex], "separator should be 0x00 after service name")

	addrStart := sepIndex + 1
	addrEnd := addrStart + len(backendAddr.Bytes())
	assert.True(t, bytes.Equal(keyBytes[addrStart:addrEnd], backendAddr.Bytes()), "address bytes should follow service name separator")
	assert.Equal(t, byte(0x00), keyBytes[addrEnd], "separator should be 0x00 after address bytes")
	assert.Equal(t, byte(0), keyBytes[addrEnd+1], "priority should be last byte")
}

func collectBackends(seq iter.Seq2[*Backend, statedb.Revision]) []*Backend {
	backends := make([]*Backend, 0)
	for be := range seq {
		backends = append(backends, be)
	}
	return backends
}

func TestListBackendsByServiceName(t *testing.T) {
	db := statedb.New()
	backends, err := NewBackendsTable(db)
	require.NoError(t, err)

	svc1 := NewServiceName("test", "svc1")
	svc2 := NewServiceName("test", "svc2")
	addr1 := NewL3n4Addr(TCP, cmtypes.MustParseAddrCluster("10.0.0.1"), 80, ScopeExternal)
	addr2 := NewL3n4Addr(TCP, cmtypes.MustParseAddrCluster("10.0.0.2"), 80, ScopeExternal)
	addr3 := NewL3n4Addr(TCP, cmtypes.MustParseAddrCluster("10.0.0.3"), 80, ScopeExternal)

	wtxn := db.WriteTxn(backends)
	insert := func(svc ServiceName, addr L3n4Addr, prio uint8) {
		be := &Backend{ServiceName: svc, Address: addr}
		be.SetSourcePriority(prio)
		_, _, err = backends.Insert(wtxn, be)
		require.NoError(t, err)
	}
	insert(svc1, addr1, 0)
	insert(svc1, addr1, 1)
	insert(svc1, addr2, 0)
	insert(svc2, addr3, 0)
	wtxn.Commit()

	rtxn := db.ReadTxn()
	seq, _ := ListBackendsByServiceName(rtxn, backends, svc1)
	bes := collectBackends(seq)
	require.Len(t, bes, 3)

	type backendIdentity struct {
		addr string
		prio uint8
	}
	got := map[backendIdentity]bool{}
	for _, be := range bes {
		assert.Equal(t, svc1, be.ServiceName)
		got[backendIdentity{be.Address.StringWithProtocol(), be.SourcePriority()}] = true
	}

	assert.True(t, got[backendIdentity{addr1.StringWithProtocol(), 0}])
	assert.True(t, got[backendIdentity{addr1.StringWithProtocol(), 1}])
	assert.True(t, got[backendIdentity{addr2.StringWithProtocol(), 0}])
}

func TestListBackendsByServiceNameAndAddress(t *testing.T) {
	db := statedb.New()
	backends, err := NewBackendsTable(db)
	require.NoError(t, err)

	svc1 := NewServiceName("test", "svc1")
	svc2 := NewServiceName("test", "svc2")
	addr1 := NewL3n4Addr(TCP, cmtypes.MustParseAddrCluster("10.0.1.1"), 80, ScopeExternal)
	addr2 := NewL3n4Addr(TCP, cmtypes.MustParseAddrCluster("10.0.1.2"), 80, ScopeExternal)

	wtxn := db.WriteTxn(backends)
	insert := func(svc ServiceName, addr L3n4Addr, prio uint8) {
		be := &Backend{ServiceName: svc, Address: addr}
		be.SetSourcePriority(prio)
		_, _, err = backends.Insert(wtxn, be)
		require.NoError(t, err)
	}
	insert(svc1, addr1, 0)
	insert(svc1, addr1, 1)
	insert(svc1, addr2, 0)
	insert(svc2, addr1, 0)
	wtxn.Commit()

	rtxn := db.ReadTxn()
	seq, _ := ListBackendsByServiceNameAndAddress(rtxn, backends, svc1, addr1)
	bes := collectBackends(seq)
	require.Len(t, bes, 2)
	for _, be := range bes {
		assert.Equal(t, svc1, be.ServiceName)
		assert.Equal(t, addr1, be.Address)
	}

	seq, _ = ListBackendsByServiceNameAndAddress(rtxn, backends, svc2, addr2)
	assert.Empty(t, collectBackends(seq))
}
