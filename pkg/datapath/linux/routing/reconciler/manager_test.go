// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package reconciler

import (
	"context"
	"log/slog"
	"net/netip"
	"testing"

	"github.com/cilium/hive/cell"
	"github.com/cilium/statedb"
	statedbReconciler "github.com/cilium/statedb/reconciler"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/endpointstate"
	"github.com/cilium/cilium/pkg/ipam"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/promise"
	testendpointmanager "github.com/cilium/cilium/pkg/testutils/endpointmanager"
	testpolicy "github.com/cilium/cilium/pkg/testutils/policy"
)

func TestEndpointRulesOwner(t *testing.T) {
	require.Equal(t, internalEndpointOwner, endpointRulesOwner(&endpoint.Endpoint{}))
	require.Equal(t, "container-a:eth0", endpointRulesOwner(newTestEndpoint(t, "container-a", "", "")))
}

func TestEndpointRulesManager(t *testing.T) {
	db := statedb.New()
	table, err := newEndpointRulesTable(db)
	require.NoError(t, err)

	manager := &endpointRulesManager{
		logger:       slog.Default(),
		db:           db,
		table:        table,
		initializing: false,
	}
	ep := newTestEndpoint(t, "container-a", "192.0.2.10", "2001:db8::10")

	manager.EndpointCreated(ep)

	v4, _, found := table.Get(db.ReadTxn(), endpointRulesAddressIndex.Query(netip.MustParseAddr("192.0.2.10")))
	require.True(t, found)
	require.Equal(t, statedbReconciler.StatusKindPending, v4.Status.Kind)
	require.Equal(t, "container-a:eth0", v4.Owner)

	v6, _, found := table.Get(db.ReadTxn(), endpointRulesAddressIndex.Query(netip.MustParseAddr("2001:db8::10")))
	require.True(t, found)
	require.Equal(t, statedbReconciler.StatusKindPending, v6.Status.Kind)
	require.Equal(t, v4.Owner, v6.Owner)

	txn := db.WriteTxn(table)
	v4 = v4.Clone().SetStatus(statedbReconciler.StatusDone())
	_, _, err = table.Insert(txn, v4)
	require.NoError(t, err)
	txn.Commit()

	// A duplicate lifecycle event must not reset a successfully reconciled
	// object to Pending.
	manager.EndpointRestored(ep)
	v4, _, found = table.Get(db.ReadTxn(), endpointRulesAddressIndex.Query(netip.MustParseAddr("192.0.2.10")))
	require.True(t, found)
	require.Equal(t, statedbReconciler.StatusKindDone, v4.Status.Kind)

	manager.EndpointDeleted(ep, endpoint.DeleteConfig{})
	_, _, found = table.Get(db.ReadTxn(), endpointRulesAddressIndex.Query(netip.MustParseAddr("192.0.2.10")))
	require.False(t, found)
	_, _, found = table.Get(db.ReadTxn(), endpointRulesAddressIndex.Query(netip.MustParseAddr("2001:db8::10")))
	require.False(t, found)
}

func TestEndpointRulesManagerFencesStaleEndpointDeletion(t *testing.T) {
	db := statedb.New()
	table, err := newEndpointRulesTable(db)
	require.NoError(t, err)

	manager := &endpointRulesManager{
		logger:       slog.Default(),
		db:           db,
		table:        table,
		initializing: false,
	}
	address := netip.MustParseAddr("192.0.2.10")
	oldEndpoint := newTestEndpoint(t, "old-container", address.String(), "")
	newEndpoint := newTestEndpoint(t, "new-container", address.String(), "")

	manager.EndpointCreated(oldEndpoint)
	oldRules, _, found := table.Get(db.ReadTxn(), endpointRulesAddressIndex.Query(address))
	require.True(t, found)

	txn := db.WriteTxn(table)
	oldRules = oldRules.Clone().SetStatus(statedbReconciler.StatusDone())
	_, _, err = table.Insert(txn, oldRules)
	require.NoError(t, err)
	txn.Commit()

	manager.EndpointCreated(newEndpoint)
	newRules, _, found := table.Get(db.ReadTxn(), endpointRulesAddressIndex.Query(address))
	require.True(t, found)
	require.NotEqual(t, oldRules.Owner, newRules.Owner)
	require.Equal(t, statedbReconciler.StatusKindPending, newRules.Status.Kind)

	manager.EndpointDeleted(oldEndpoint, endpoint.DeleteConfig{
		EndpointOwnsIP: func(netip.Addr) bool { return false },
	})
	current, _, found := table.Get(db.ReadTxn(), endpointRulesAddressIndex.Query(address))
	require.True(t, found)
	require.Equal(t, newRules.Owner, current.Owner)

	manager.EndpointDeleted(newEndpoint, endpoint.DeleteConfig{
		EndpointOwnsIP: func(netip.Addr) bool { return false },
	})
	_, _, found = table.Get(db.ReadTxn(), endpointRulesAddressIndex.Query(address))
	require.True(t, found)

	manager.EndpointDeleted(newEndpoint, endpoint.DeleteConfig{
		EndpointOwnsIP: func(netip.Addr) bool { return true },
	})
	_, _, found = table.Get(db.ReadTxn(), endpointRulesAddressIndex.Query(address))
	require.False(t, found)
}

func TestEndpointRulesManagerInitialization(t *testing.T) {
	db := statedb.New()
	table, err := newEndpointRulesTable(db)
	require.NoError(t, err)

	live := newTestEndpoint(t, "live-container", "192.0.2.10", "")
	deletedDuringInitialization := newTestEndpoint(t, "deleted-container", "192.0.2.11", "")
	replacedDuringInitialization := newTestEndpoint(t, "old-container", "192.0.2.12", "")
	replacement := newTestEndpoint(t, "new-container", "192.0.2.12", "")
	endpointManager := testendpointmanager.NewMockEndpointManager()

	ipamManager := ipam.NewIPAM(ipam.NewIPAMParams{
		Logger:      slog.Default(),
		AgentConfig: &option.DaemonConfig{},
	})
	ipamManager.RestoreFinished()

	resolver, restorerPromise := promise.New[endpointstate.Restorer]()
	resolver.Resolve(immediateRestorer{})
	manager := newEndpointRulesManager(
		slog.Default(),
		db,
		table,
		ipamManager,
		endpointManager,
		restorerPromise,
	)

	initialized, _ := table.Initialized(db.ReadTxn())
	require.False(t, initialized)

	// Subscription is established before endpoint restoration starts, so
	// restored endpoints and concurrent lifecycle events are queued until the
	// IPAM and endpoint restoration barriers have completed.
	manager.EndpointRestored(live)
	manager.EndpointCreated(deletedDuringInitialization)
	manager.EndpointDeleted(deletedDuringInitialization, endpoint.DeleteConfig{})
	manager.EndpointCreated(replacedDuringInitialization)
	manager.EndpointCreated(replacement)
	manager.EndpointDeleted(replacedDuringInitialization, endpoint.DeleteConfig{
		EndpointOwnsIP: func(netip.Addr) bool { return false },
	})
	require.Zero(t, table.NumObjects(db.ReadTxn()))

	health, _ := cell.NewSimpleHealth()
	require.NoError(t, manager.initialize(t.Context(), health))

	initialized, _ = table.Initialized(db.ReadTxn())
	require.True(t, initialized)
	require.Equal(t, 2, table.NumObjects(db.ReadTxn()))

	_, _, found := table.Get(db.ReadTxn(), endpointRulesAddressIndex.Query(live.IPv4Address()))
	require.True(t, found)
	_, _, found = table.Get(db.ReadTxn(), endpointRulesAddressIndex.Query(deletedDuringInitialization.IPv4Address()))
	require.False(t, found)
	rules, _, found := table.Get(db.ReadTxn(), endpointRulesAddressIndex.Query(replacement.IPv4Address()))
	require.True(t, found)
	require.Equal(t, endpointRulesOwner(replacement), rules.Owner)
}

func newTestEndpoint(t *testing.T, containerID, ipv4, ipv6 string) *endpoint.Endpoint {
	t.Helper()

	logger := slog.Default()
	ep, err := endpoint.NewEndpointFromChangeModel(
		endpoint.EndpointParams{
			Logger:     logger,
			PolicyRepo: policy.NewPolicyRepository(logger, nil, nil, nil, nil, testpolicy.NewPolicyMetricsNoop()),
		},
		nil,
		nil,
		&models.EndpointChangeRequest{
			ContainerID:            containerID,
			ContainerInterfaceName: "eth0",
		},
		nil,
	)
	require.NoError(t, err)
	if ipv4 != "" {
		ep.IPv4 = netip.MustParseAddr(ipv4)
	}
	if ipv6 != "" {
		ep.IPv6 = netip.MustParseAddr(ipv6)
	}
	return ep
}

type immediateRestorer struct{}

func (immediateRestorer) WaitForEndpointRestoreWithoutRegeneration(context.Context) error {
	return nil
}

func (immediateRestorer) WaitForEndpointRestore(context.Context) error {
	return nil
}

func (immediateRestorer) WaitForInitialPolicy(context.Context) error {
	return nil
}
