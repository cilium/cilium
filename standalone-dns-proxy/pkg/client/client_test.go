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

	client := createGRPCClient(logger, nil, nil)

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
		Identity: identity.NumericIdentity(100),
		SelPol:   nil,
	}
	_, _, err = table.Insert(txn, dnsRule)
	require.NoError(t, err)
	txn.Commit()

	// Read back the data
	rtxn := db.ReadTxn()
	rule, _, found := table.Get(rtxn, service.PolicyRulesIndex.Query(identity.NumericIdentity(100)))
	require.True(t, found)
	require.Equal(t, identity.NumericIdentity(100), rule.Identity)
	require.Nil(t, rule.SelPol)
}

func updateMapping(t *testing.T, client *GRPCClient, id uint64, ident identity.NumericIdentity, ip string) {
	t.Helper()
	input := []*pb.IdentityToEndpointMapping{
		{
			Identity: ident.Uint32(),
			EndpointInfo: []*pb.EndpointInfo{
				{
					Id: id,
					Ip: [][]byte{[]byte(ip)},
				},
			},
		},
	}

	err := client.updateIPToEndpoint(input)
	require.NoError(t, err)
}

func checkMapping(t *testing.T, client *GRPCClient, ip string, expectedID uint64, expectedIdent identity.NumericIdentity, shouldExist bool) {
	t.Helper()
	rtxn := client.db.ReadTxn()
	prefix, err := netip.ParsePrefix(ip)
	require.NoError(t, err)
	mapping, _, found := client.ipToEndpointTable.Get(rtxn, IdIPToEndpointIndex.Query(prefix))
	if shouldExist {
		require.True(t, found)
		require.Equal(t, prefix, mapping.IP)
		require.Equal(t, expectedIdent, mapping.Endpoint.Identity)
		require.Equal(t, expectedID, mapping.Endpoint.ID)
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

	// Create DNSRules and IPtoIdentity tables
	dnsTable, err := newDNSRulesTable(db)
	require.NoError(t, err)
	require.NotNil(t, dnsTable)

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

	// Expected: 1 entry for 192.168.1.2, identity 2, ID 200
	updateMapping(t, client, 200, identity.NumericIdentity(2), "192.168.1.2")
	checkMapping(t, client, "192.168.1.2", 200, identity.NumericIdentity(2), true)
	checkMapping(t, client, "192.168.1.1", 100, identity.NumericIdentity(1), false)

	// Update mapping - modify existing entry
	updateMapping(t, client, 200, identity.NumericIdentity(3), "192.168.1.2")
	checkMapping(t, client, "192.168.1.2", 200, identity.NumericIdentity(3), true)
}
