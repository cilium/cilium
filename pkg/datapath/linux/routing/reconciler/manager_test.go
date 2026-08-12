// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package reconciler

import (
	"log/slog"
	"net/netip"
	"testing"

	"github.com/cilium/statedb"
	statedbReconciler "github.com/cilium/statedb/reconciler"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/api/v1/models"
	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/policy"
	testpolicy "github.com/cilium/cilium/pkg/testutils/policy"
)

func TestEndpointRulesManager(t *testing.T) {
	db := statedb.New()
	table, err := newEndpointRulesTable(db)
	require.NoError(t, err)

	manager := newEndpointRulesManager(slog.Default(), db, table)
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

	manager := newEndpointRulesManager(slog.Default(), db, table)
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
