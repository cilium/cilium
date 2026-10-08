// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package restapi

import (
	"testing"

	"github.com/cilium/statedb"
	"github.com/cilium/statedb/reconciler"
	"github.com/go-openapi/runtime/middleware"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/api/v1/models"
	daemonrestapi "github.com/cilium/cilium/api/v1/server/restapi/daemon"
	"github.com/cilium/cilium/pkg/node"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
	"github.com/cilium/cilium/pkg/source"
	"github.com/cilium/cilium/pkg/time"
)

func newTestHandler(t *testing.T) (
	*getClusterNodesRESTAPIHandler,
	*statedb.DB,
	statedb.RWTable[*node.Node],
) {
	t.Helper()
	db := statedb.New()
	nodes, err := node.NewNodeTable(db)
	require.NoError(t, err)
	handler := newGetClusterNodesRESTAPIHandler(db, nodes)
	return handler.(*getClusterNodesRESTAPIHandler), db, nodes
}

func responsePayload(
	t *testing.T,
	responder middleware.Responder,
) *models.ClusterNodeStatus {
	t.Helper()
	response, ok := responder.(*daemonrestapi.GetClusterNodesOK)
	require.True(t, ok)
	return response.Payload
}

func upsertNode(
	db *statedb.DB,
	nodes statedb.RWTable[*node.Node],
	n *node.Node,
) {
	txn := db.WriteTxn(nodes)
	nodes.Insert(txn, n)
	txn.Commit()
}

func deleteNode(
	db *statedb.DB,
	nodes statedb.RWTable[*node.Node],
	n *node.Node,
) {
	txn := db.WriteTxn(nodes)
	nodes.Delete(txn, n)
	txn.Commit()
}

func TestGetClusterNodes(t *testing.T) {
	h, db, nodes := newTestHandler(t)
	n1 := &node.Node{Node: nodeTypes.Node{
		Name:          "node-1",
		Cluster:       "cluster-1",
		Source:        source.CustomResource,
		EncryptionKey: 1,
	}}
	upsertNode(db, nodes, n1)

	// A request without a client ID returns a snapshot without creating a
	// change-tracking client.
	payload := responsePayload(t, h.Handle(
		daemonrestapi.GetClusterNodesParams{},
	))
	require.Zero(t, payload.ClientID)
	require.Equal(t, []*models.NodeElement{n1.GetModel()}, payload.NodesAdded)
	require.Empty(t, h.clients)

	// A request with an unknown client ID creates a client and returns its
	// initial snapshot.
	randSrc.Seed(0, 0)
	var unknownClient int64
	payload = responsePayload(t, h.Handle(
		daemonrestapi.GetClusterNodesParams{ClientID: &unknownClient},
	))
	clientID := payload.ClientID
	require.NotZero(t, clientID)
	require.Equal(t, []*models.NodeElement{n1.GetModel()}, payload.NodesAdded)
	require.Contains(t, h.clients, clientID)

	// Reconciler status updates must not be exposed as node updates.
	n1WithStatus := n1.DeepCopy()
	n1WithStatus.Statuses = n1WithStatus.Statuses.Set(
		"test",
		reconciler.StatusPending(),
	)
	upsertNode(db, nodes, n1WithStatus)
	payload = responsePayload(t, h.Handle(
		daemonrestapi.GetClusterNodesParams{ClientID: &clientID},
	))
	require.Empty(t, payload.NodesAdded)
	require.Empty(t, payload.NodesRemoved)

	// Desired node changes are returned as removal of the old object and
	// addition of the new object.
	n1Updated := n1WithStatus.DeepCopy()
	n1Updated.EncryptionKey = 2
	upsertNode(db, nodes, n1Updated)
	payload = responsePayload(t, h.Handle(
		daemonrestapi.GetClusterNodesParams{ClientID: &clientID},
	))
	require.Equal(
		t,
		[]*models.NodeElement{n1Updated.GetModel()},
		payload.NodesAdded,
	)
	require.Equal(
		t,
		[]*models.NodeElement{n1WithStatus.GetModel()},
		payload.NodesRemoved,
	)

	deleteNode(db, nodes, n1Updated)
	payload = responsePayload(t, h.Handle(
		daemonrestapi.GetClusterNodesParams{ClientID: &clientID},
	))
	require.Empty(t, payload.NodesAdded)
	require.Equal(
		t,
		[]*models.NodeElement{n1Updated.GetModel()},
		payload.NodesRemoved,
	)
}

func TestGetClusterNodesCoalescesChanges(t *testing.T) {
	h, db, nodes := newTestHandler(t)
	randSrc.Seed(0, 0)
	var unknownClient int64
	payload := responsePayload(t, h.Handle(
		daemonrestapi.GetClusterNodesParams{ClientID: &unknownClient},
	))
	clientID := payload.ClientID

	// A node added and removed between polls was never visible to the client.
	n := &node.Node{Node: nodeTypes.Node{
		Name:    "transient",
		Cluster: "cluster-1",
		Source:  source.CustomResource,
	}}
	upsertNode(db, nodes, n)
	deleteNode(db, nodes, n)
	payload = responsePayload(t, h.Handle(
		daemonrestapi.GetClusterNodesParams{ClientID: &clientID},
	))
	require.Empty(t, payload.NodesAdded)
	require.Empty(t, payload.NodesRemoved)
}

func TestCleanupClients(t *testing.T) {
	h, _, _ := newTestHandler(t)
	randSrc.Seed(0, 0)
	var unknownClient int64
	payload := responsePayload(t, h.Handle(
		daemonrestapi.GetClusterNodesParams{ClientID: &unknownClient},
	))
	expiredClientID := payload.ClientID
	h.clients[expiredClientID].lastSync = time.Now().Add(-clientGCTimeout)

	// Cleanup is performed when another client is created.
	unknownClient = -1
	payload = responsePayload(t, h.Handle(
		daemonrestapi.GetClusterNodesParams{ClientID: &unknownClient},
	))
	require.NotZero(t, payload.ClientID)
	require.NotEqual(t, expiredClientID, payload.ClientID)
	require.NotContains(t, h.clients, expiredClientID)
	require.Contains(t, h.clients, payload.ClientID)
}
