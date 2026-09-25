// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package namemanager

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

func TestUpdateIPsForNamePersistsGlobalFQDNState(t *testing.T) {
	db := statedb.New()
	table, err := fqdn.NewFQDNStateTable(db)
	require.NoError(t, err)
	manager := &manager{
		logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		params: ManagerParams{DB: db, FQDNTable: table},
	}

	lookupTime := time.Unix(1700000000, 0).UTC()
	ip := netip.MustParseAddr("1.1.1.1")
	manager.updateIPsForName(lookupTime, "example.com", []netip.Addr{ip}, 60)
	manager.updateIPsForName(lookupTime.Add(time.Second), "example.com", []netip.Addr{ip}, 10)

	mapping, _, found := table.Get(db.ReadTxn(), fqdn.QueryByName("example.com"))
	require.True(t, found)
	require.Equal(t, ip, mapping.IP)
	require.Equal(t, lookupTime.Add(60*time.Second), mapping.ExpirationTime)
}
