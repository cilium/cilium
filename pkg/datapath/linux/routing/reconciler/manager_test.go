// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package reconciler

import (
	"context"
	"log/slog"
	"net/netip"
	"testing"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/cilium/statedb"
	statedbReconciler "github.com/cilium/statedb/reconciler"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/api/v1/models"
	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/endpointstate"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/ipam"
	ipamOption "github.com/cilium/cilium/pkg/ipam/option"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/promise"
	testendpointmanager "github.com/cilium/cilium/pkg/testutils/endpointmanager"
	testpolicy "github.com/cilium/cilium/pkg/testutils/policy"
)

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
	ep := newTestEndpoint(t, 1, "container-a", "192.0.2.10", "2001:db8::10")

	manager.EndpointCreated(ep)

	v4, _, found := table.Get(db.ReadTxn(), endpointRulesAddressIndex.Query(netip.MustParseAddr("192.0.2.10")))
	require.True(t, found)
	require.Equal(t, statedbReconciler.StatusKindPending, v4.Status.Kind)
	require.Equal(t, "container-a:eth0", v4.Owner)
	require.Equal(t, ep.GetLifecycleGeneration(), v4.Generation)

	v6, _, found := table.Get(db.ReadTxn(), endpointRulesAddressIndex.Query(netip.MustParseAddr("2001:db8::10")))
	require.True(t, found)
	require.Equal(t, statedbReconciler.StatusKindPending, v6.Status.Kind)
	require.Equal(t, "container-a:eth0", v6.Owner)
	require.Equal(t, ep.GetLifecycleGeneration(), v6.Generation)

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
	// same owner and IP address but different lifecycle generations
	oldEndpoint := newTestEndpoint(t, 1, "container-a", address.String(), "")
	newEndpoint := newTestEndpoint(t, 2, "container-a", address.String(), "")

	// insert the old endpoint into the table
	manager.EndpointCreated(oldEndpoint)
	oldRules, _, found := table.Get(db.ReadTxn(), endpointRulesAddressIndex.Query(address))
	require.True(t, found)

	txn := db.WriteTxn(table)
	oldRules = oldRules.Clone().SetStatus(statedbReconciler.StatusDone())
	_, _, err = table.Insert(txn, oldRules)
	require.NoError(t, err)
	txn.Commit()

	// simulate the creation of a new endpoint with the same owner and IP but a different lifecycle generation
	manager.EndpointCreated(newEndpoint)
	newRules, _, found := table.Get(db.ReadTxn(), endpointRulesAddressIndex.Query(address))
	require.True(t, found)
	require.Equal(t, oldRules.Owner, newRules.Owner)
	require.NotEqual(t, oldRules.Generation, newRules.Generation)
	require.Equal(t, statedbReconciler.StatusKindPending, newRules.Status.Kind)

	// a delay in dispatching the deletion event should not remove new endpoint (and its rules) from the table
	manager.EndpointDeleted(oldEndpoint, endpoint.DeleteConfig{})
	current, _, found := table.Get(db.ReadTxn(), endpointRulesAddressIndex.Query(address))
	require.True(t, found)
	require.Equal(t, newRules.Owner, current.Owner)
	require.Equal(t, newRules.Generation, current.Generation)

	// deleting the new endpoint should remove it from the table
	manager.EndpointDeleted(newEndpoint, endpoint.DeleteConfig{})
	_, _, found = table.Get(db.ReadTxn(), endpointRulesAddressIndex.Query(address))
	require.False(t, found)
}

func TestEndpointRulesManagerInitialization(t *testing.T) {
	db := statedb.New()
	table, err := newEndpointRulesTable(db)
	require.NoError(t, err)

	live := newTestEndpoint(t, 1, "live-container", "192.0.2.10", "")
	deletedDuringInitialization := newTestEndpoint(t, 2, "deleted-container", "192.0.2.11", "")
	replacedDuringInitialization := newTestEndpoint(t, 3, "reused-container", "192.0.2.12", "")
	replacement := newTestEndpoint(t, 4, "reused-container", "192.0.2.12", "")
	endpointManager := testendpointmanager.NewMockEndpointManager()

	ipamManager := ipam.NewIPAM(ipam.NewIPAMParams{
		Logger:      slog.Default(),
		AgentConfig: &option.DaemonConfig{},
	})
	ipamManager.RestoreFinished()

	resolver, restorerPromise := promise.New[endpointstate.Restorer]()
	resolver.Resolve(fakeRestorer{})
	var jobGroup job.Group
	require.NoError(t, hive.New(
		cell.Invoke(func(group job.Group) {
			jobGroup = group
		}),
	).Populate(slog.Default()))

	manager := newEndpointRulesManager(endpointRulesManagerParams{
		Logger:          slog.Default(),
		Lifecycle:       cell.NewDefaultLifecycle(nil, 0, 0),
		JobGroup:        jobGroup,
		DB:              db,
		Table:           table,
		DaemonConfig:    &option.DaemonConfig{IPAM: ipamOption.IPAMENI},
		IPAM:            ipamManager,
		EndpointManager: endpointManager,
		Restorer:        restorerPromise,
	})

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
	manager.EndpointDeleted(replacedDuringInitialization, endpoint.DeleteConfig{})
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
	require.Equal(t, replacement.GetLifecycleGeneration(), rules.Generation)
}

func newTestEndpoint(t *testing.T, generation uint64, containerID, ipv4, ipv6 string) *endpoint.Endpoint {
	t.Helper()

	logger := slog.Default()
	ep, err := endpoint.NewEndpointFromChangeModel(
		endpoint.EndpointParams{
			Logger:     logger,
			PolicyRepo: policy.NewPolicyRepository(logger, cmtypes.DefaultClusterInfo.ID, nil, nil, nil, nil, testpolicy.NewPolicyMetricsNoop()),
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
	ep.InitLifecycleGeneration(generation)
	if ipv4 != "" {
		ep.IPv4 = netip.MustParseAddr(ipv4)
	}
	if ipv6 != "" {
		ep.IPv6 = netip.MustParseAddr(ipv6)
	}
	return ep
}

type fakeRestorer struct{}

func (fakeRestorer) WaitForEndpointRestoreWithoutRegeneration(context.Context) error {
	return nil
}

func (fakeRestorer) WaitForEndpointRestore(context.Context) error {
	return nil
}

func (fakeRestorer) WaitForInitialPolicy(context.Context) error {
	return nil
}
