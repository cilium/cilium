// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package client

import (
	"log/slog"
	"net/netip"
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/cilium/statedb"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/fqdn/service"
	"github.com/cilium/cilium/pkg/identity"

	pb "github.com/cilium/cilium/api/v1/standalone-dns-proxy"
)

func TestCreatecreateGRPCClient(t *testing.T) {
	logger := slog.Default()

	client := createGRPCClient(logger, nil, nil, nil)

	require.NotNil(t, client)
}

// Note: In the future PRs, the test case will be updated to actually check the dns rules table scenarios.
func TestNewDNSRulesTable(t *testing.T) {
	// Create a new StateDB instance
	db := statedb.New()

	// Test successful table creation
	table, err := newDNSRulesTable(db)
	require.NoError(t, err)
	require.NotNil(t, table)

	// Test table insertion and retrieval
	txn := db.WriteTxn(table)
	dnsRule := service.PolicyRules{
		Identity:    identity.NumericIdentity(100),
		PolicyRules: nil,
	}
	_, _, err = table.Insert(txn, dnsRule)
	require.NoError(t, err)
	txn.Commit()

	// Read back the data
	rtxn := db.ReadTxn()
	rule, _, found := table.Get(rtxn, service.PolicyRulesIndex.Query(identity.NumericIdentity(100)))
	require.True(t, found)
	require.Equal(t, identity.NumericIdentity(100), rule.Identity)
	require.Nil(t, rule.PolicyRules)
}

func updateMapping(t *testing.T, client *GRPCClient, id uint64, ident identity.NumericIdentity, ip string) {
	t.Helper()
	ipAddr, err := netip.ParseAddr(ip)
	require.NoError(t, err)
	input := []*pb.IdentityToEndpointMapping{
		{
			Identity: ident.Uint32(),
			EndpointInfo: []*pb.EndpointInfo{
				{
					Id: id,
					Ip: [][]byte{ipAddr.AsSlice()},
				},
			},
		},
	}

	err = client.updateIPToEndpoint(input)
	require.NoError(t, err)
}

func checkMapping(t *testing.T, client *GRPCClient, ip string, expectedID uint64, expectedIdent identity.NumericIdentity, shouldExist bool) {
	t.Helper()
	rtxn := client.db.ReadTxn()
	addr, err := netip.ParseAddr(ip)
	require.NoError(t, err)
	mapping, _, found := client.ipToEndpointTable.Get(rtxn, IdIPToEndpointIndex.Query(addr))
	if shouldExist {
		require.True(t, found)
		require.Equal(t, []netip.Addr{addr}, mapping.IP)
		require.Equal(t, expectedIdent, mapping.Identity)
		require.Equal(t, expectedID, mapping.ID)
	} else {
		require.False(t, found)
	}
}

func TestNewIPtoIdentityTable(t *testing.T) {
	// Create a new StateDB instance
	db := statedb.New()

	// Test successful table creation
	ipTable, err := NewIPtoEndpointTable(db)
	require.NoError(t, err)
	require.NotNil(t, ipTable)

	logger := hivetest.Logger(t)
	client := &GRPCClient{
		logger:            logger,
		db:                db,
		ipToEndpointTable: ipTable,
	}

	// Initial check - table should be empty
	checkMapping(t, client, "192.168.1.1", 100, identity.NumericIdentity(1), false)
	checkMapping(t, client, "192.168.1.2", 200, identity.NumericIdentity(2), false)

	// Expected: 1 entry for 192.168.1.1, identity 1, ID 100
	updateMapping(t, client, 100, identity.NumericIdentity(1), "192.168.1.1")
	checkMapping(t, client, "192.168.1.1", 100, identity.NumericIdentity(1), true)
	checkMapping(t, client, "192.168.1.2", 200, identity.NumericIdentity(2), false)

	updateMapping(t, client, 100, identity.NumericIdentity(1), "192.168.1.1")
	checkMapping(t, client, "192.168.1.1", 100, identity.NumericIdentity(1), true)
	checkMapping(t, client, "192.168.1.2", 200, identity.NumericIdentity(2), false)

	// Expected: 1 entry for 192.168.1.2, identity 2, ID 200
	updateMapping(t, client, 200, identity.NumericIdentity(2), "192.168.1.2")
	checkMapping(t, client, "192.168.1.2", 200, identity.NumericIdentity(2), true)
	checkMapping(t, client, "192.168.1.1", 100, identity.NumericIdentity(1), false)

	// Update mapping - modify existing entry
	updateMapping(t, client, 200, identity.NumericIdentity(3), "192.168.1.2")
	checkMapping(t, client, "192.168.1.2", 200, identity.NumericIdentity(3), true)
}

func checkPrefixMapping(t *testing.T, client *GRPCClient, prefix string, expectedIdent identity.NumericIdentity, shouldExist bool) {
	t.Helper()
	rtxn := client.db.ReadTxn()
	pfx, err := netip.ParsePrefix(prefix)
	require.NoError(t, err)
	mapping, _, found := client.prefixToIdentityTable.Get(rtxn, PrefixToIdentityIndex.Query(pfx))
	if shouldExist {
		require.True(t, found)
		require.Equal(t, []netip.Prefix{pfx}, mapping.Prefix)
		require.Equal(t, expectedIdent, mapping.Identity)
	} else {
		require.False(t, found)
	}
}

func updatePrefixMapping(t *testing.T, client *GRPCClient, ident identity.NumericIdentity, prefix string) {
	t.Helper()
	ipBytes, err := netip.MustParsePrefix(prefix).MarshalBinary()
	require.NoError(t, err)
	input := []*pb.IdentityToPrefixMapping{
		{
			Identity: ident.Uint32(),
			Prefix:   [][]byte{ipBytes},
		},
	}

	err = client.updatePrefixToIdentity(input)
	require.NoError(t, err)
}

func TestNewPrefixToIdentityTable(t *testing.T) {
	// Create a new StateDB instance
	db := statedb.New()

	// Test successful table creation
	prefixTable, err := NewPrefixToIdentityTable(db)
	require.NoError(t, err)
	require.NotNil(t, prefixTable)

	logger := hivetest.Logger(t)
	client := &GRPCClient{
		logger:                logger,
		db:                    db,
		prefixToIdentityTable: prefixTable,
	}

	// Initial check - table should be empty
	checkPrefixMapping(t, client, "192.168.1.1/24", identity.NumericIdentity(1), false)
	checkPrefixMapping(t, client, "192.168.1.2/16", identity.NumericIdentity(2), false)

	// Expected: 1 entry for 192.168.1.1/24, identity 1
	updatePrefixMapping(t, client, identity.NumericIdentity(1), "192.168.1.1/24")
	checkPrefixMapping(t, client, "192.168.1.1/24", identity.NumericIdentity(1), true)
	checkPrefixMapping(t, client, "192.168.1.2/32", identity.NumericIdentity(2), false)

	// Expected: 1 entry for 192.168.1.2/16, identity 2
	updatePrefixMapping(t, client, identity.NumericIdentity(2), "192.168.1.2/16")
	checkPrefixMapping(t, client, "192.168.1.2/16", identity.NumericIdentity(2), true)
	checkPrefixMapping(t, client, "192.168.1.1/32", identity.NumericIdentity(1), false)

	// Update mapping - modify existing entry
	updatePrefixMapping(t, client, identity.NumericIdentity(3), "192.168.1.2/16")
	checkPrefixMapping(t, client, "192.168.1.2/16", identity.NumericIdentity(3), true)
}
