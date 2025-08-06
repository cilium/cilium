// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package client

import (
	"log/slog"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cilium/statedb"

	"github.com/cilium/cilium/pkg/fqdn/service"
	"github.com/cilium/cilium/pkg/identity"
)

func TestCreatecreateGRPCClient(t *testing.T) {
	logger := slog.Default()

	client := createGRPCClient(logger)

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

// Note: In the future PRs, the test case will be updated to actually check the ip<>identity mapping scenarios.
func TestNewIPtoIdentityTable(t *testing.T) {
	// Create a new StateDB instance
	db := statedb.New()

	// Test successful table creation
	table, err := newIPtoIdentityTable(db)
	require.NoError(t, err)
	require.NotNil(t, table)

	// Test table insertion and retrieval
	txn := db.WriteTxn(table)
	ip := netip.MustParseAddr("192.168.1.1")
	ipToIdentity := IPtoIdentity{
		IP:       ip,
		Identity: identity.NumericIdentity(200),
	}
	_, _, err = table.Insert(txn, ipToIdentity)
	require.NoError(t, err)
	txn.Commit()

	// Read back the data
	rtxn := db.ReadTxn()
	mapping, _, found := table.Get(rtxn, idIPToIdentityIndex.Query(ip))
	require.True(t, found)
	require.Equal(t, ip, mapping.IP)
	require.Equal(t, identity.NumericIdentity(200), mapping.Identity)
}
