// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package messagehandler

import (
	"io"
	"log/slog"
	"net/netip"
	"testing"
	"time"

	"github.com/cilium/statedb"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/fqdn"
)

func TestUpdateEndpointFQDNState(t *testing.T) {
	db := statedb.New()
	tbl, err := fqdn.NewEndpointFQDNStateTable(db)
	require.NoError(t, err)
	handler := &dnsMessageHandler{
		logger:            slog.New(slog.NewTextHandler(io.Discard, nil)),
		db:                db,
		endpointFQDNTable: tbl,
	}

	lookupTime := time.Unix(1700000000, 0).UTC()
	ip := netip.MustParseAddr("1.1.1.1")
	handler.updateEndpointFQDNState(42, "example.com", []netip.Addr{ip}, lookupTime, 60)
	handler.updateEndpointFQDNState(42, "example.com", []netip.Addr{ip}, lookupTime.Add(time.Second), 10)

	rows := statedb.Collect(tbl.List(db.ReadTxn(), fqdn.QueryEndpointFQDNByEndpoint(42)))
	require.Len(t, rows, 1)
	require.Equal(t, lookupTime.Add(60*time.Second), rows[0].ExpirationTime)
}
