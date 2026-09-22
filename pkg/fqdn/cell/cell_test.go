// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cell

import (
	"io"
	"log/slog"
	"net/netip"
	"testing"

	"github.com/cilium/statedb"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/fqdn"
)

func TestEndpointFQDNStateCleanup(t *testing.T) {
	db := statedb.New()
	table, err := fqdn.NewEndpointFQDNStateTable(db)
	require.NoError(t, err)
	ip := netip.MustParseAddr("1.1.1.1")
	txn := db.WriteTxn(table)
	for _, id := range []uint16{42, 43} {
		_, _, err := table.Insert(txn, fqdn.EndpointFQDNMapping{
			EndpointID: id,
			Name:       "example.com.",
			IP:         ip,
		})
		require.NoError(t, err)
	}
	txn.Commit()

	subscriber := endpointFQDNStateCleanup{
		db:     db,
		table:  table,
		logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	subscriber.EndpointDeleted(&endpoint.Endpoint{ID: 42}, endpoint.DeleteConfig{})
	require.Empty(t, statedb.Collect(table.List(db.ReadTxn(), fqdn.QueryEndpointFQDNByEndpoint(42))))
	require.Len(t, statedb.Collect(table.List(db.ReadTxn(), fqdn.QueryEndpointFQDNByEndpoint(43))), 1)
	subscriber.EndpointCreated(&endpoint.Endpoint{ID: 43})
	require.Empty(t, statedb.Collect(table.List(db.ReadTxn(), fqdn.QueryEndpointFQDNByEndpoint(43))))
}
