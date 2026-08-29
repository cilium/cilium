// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package fqdn

import (
	"encoding/json"
	"net/netip"
	"path/filepath"
	"testing"
	"time"

	"github.com/cilium/statedb"
	"github.com/stretchr/testify/require"
)

func TestFQDNStateTableOperations(t *testing.T) {
	db := statedb.New()
	tbl, err := NewFQDNStateTable(db)
	require.NoError(t, err)

	now := time.Unix(1700000000, 0).UTC()
	entry1 := FQDNMapping{
		Name:           "example.com",
		IP:             netip.MustParseAddr("1.1.1.1"),
		LookupTime:     now,
		TTL:            120,
		ExpirationTime: now.Add(120 * time.Second),
	}
	entry2 := FQDNMapping{
		Name:           "example.com",
		IP:             netip.MustParseAddr("2.2.2.2"),
		LookupTime:     now,
		TTL:            180,
		ExpirationTime: now.Add(180 * time.Second),
	}

	txn := db.WriteTxn(tbl)
	_, _, err = tbl.Insert(txn, entry1)
	require.NoError(t, err)
	_, _, err = tbl.Insert(txn, entry2)
	require.NoError(t, err)
	txn.Commit()

	rtxn := db.ReadTxn()
	gotByKey, rev, found := tbl.Get(rtxn, fqdnStatePrimaryIndex.Query(FQDNTableKey{Name: entry1.Name, IP: entry1.IP}))
	require.True(t, found)
	require.Equal(t, entry1.Name, gotByKey.Name)
	require.NotZero(t, rev)

	byName := statedb.Collect(tbl.List(rtxn, QueryByName(entry1.Name)))
	require.Len(t, byName, 2)

	byIP := statedb.Collect(tbl.List(rtxn, QueryByIP(entry1.IP)))
	require.Len(t, byIP, 1)

	byExpiration := statedb.Collect(tbl.List(rtxn, QueryByExpiration(entry2.ExpirationTime)))
	require.Len(t, byExpiration, 1)
}

func TestFQDNStateTablePersistenceRoundTrip(t *testing.T) {
	db := statedb.New()
	tbl, err := NewFQDNStateTable(db)
	require.NoError(t, err)

	now := time.Now().UTC().Truncate(time.Second)
	entry := FQDNMapping{
		Name:           "persist.example.com",
		IP:             netip.MustParseAddr("10.0.0.5"),
		LookupTime:     now,
		TTL:            300,
		ExpirationTime: now.Add(300 * time.Second),
	}

	txn := db.WriteTxn(tbl)
	_, _, err = tbl.Insert(txn, entry)
	require.NoError(t, err)
	txn.Commit()

	path := filepath.Join(t.TempDir(), "fqdn-state.json")
	require.NoError(t, PersistFQDNState(db, tbl.ToTable(), path))

	restoredDB := statedb.New()
	restoredTable, err := NewFQDNStateTable(restoredDB)
	require.NoError(t, err)
	restoreTxn := restoredDB.WriteTxn(restoredTable)
	require.NoError(t, RestoreFQDNState(restoreTxn, restoredTable, path))
	restoreTxn.Commit()

	rtxn := restoredDB.ReadTxn()
	got, _, found := restoredTable.Get(rtxn, fqdnStatePrimaryIndex.Query(FQDNTableKey{Name: entry.Name, IP: entry.IP}))
	require.True(t, found)
	require.Equal(t, entry.Name, got.Name)
	require.Equal(t, entry.IP, got.IP)
	require.Equal(t, entry.TTL, got.TTL)
}

func TestEndpointFQDNStateTableQueries(t *testing.T) {
	db := statedb.New()
	tbl, err := NewEndpointFQDNStateTable(db)
	require.NoError(t, err)

	now := time.Unix(1700000000, 0).UTC()
	entries := []EndpointFQDNMapping{
		{EndpointID: 42, Name: "example.com", IP: netip.MustParseAddr("1.1.1.1"), LookupTime: now, TTL: 60, ExpirationTime: now.Add(time.Minute)},
		{EndpointID: 42, Name: "example.org", IP: netip.MustParseAddr("1.1.1.1"), LookupTime: now, TTL: 60, ExpirationTime: now.Add(time.Minute)},
		{EndpointID: 43, Name: "example.com", IP: netip.MustParseAddr("1.1.1.1"), LookupTime: now, TTL: 60, ExpirationTime: now.Add(time.Minute)},
	}

	txn := db.WriteTxn(tbl)
	for _, entry := range entries {
		_, _, err := tbl.Insert(txn, entry)
		require.NoError(t, err)
	}
	txn.Commit()

	rtxn := db.ReadTxn()
	require.Len(t, statedb.Collect(tbl.List(rtxn, QueryEndpointFQDNByEndpoint(42))), 2)
	require.Len(t, statedb.Collect(tbl.List(rtxn, QueryEndpointFQDNByName("example.com"))), 2)
	require.Len(t, statedb.Collect(tbl.List(rtxn, QueryEndpointFQDNByIP(netip.MustParseAddr("1.1.1.1")))), 3)
}

func TestFQDNStateEventRoundTrip(t *testing.T) {
	event := FQDNStateEvent{Rows: []FQDNMapping{{
		Name:           "example.com",
		IP:             netip.MustParseAddr("1.1.1.1"),
		LookupTime:     time.Unix(1700000000, 0).UTC(),
		TTL:            60,
		ExpirationTime: time.Unix(1700000060, 0).UTC(),
	}}}

	data, err := event.MarshalBinary()
	require.NoError(t, err)
	require.True(t, json.Valid(data))
	restored, err := UnmarshalFQDNStateEvent(data)
	require.NoError(t, err)
	require.Equal(t, event, restored)
}
