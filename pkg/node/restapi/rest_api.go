// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package restapi

import (
	"math/rand/v2"
	"slices"

	"github.com/cilium/statedb"
	"github.com/go-openapi/runtime/middleware"

	"github.com/cilium/cilium/api/v1/models"
	daemonrestapi "github.com/cilium/cilium/api/v1/server/restapi/daemon"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/node"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
	"github.com/cilium/cilium/pkg/time"
)

var (
	// randSrc is seeded to the current time by default but can be reseeded in
	// tests so client ID allocation is deterministic.
	randSrc = rand.NewPCG(uint64(time.Now().UnixNano()), 0)
	randGen = rand.New(randSrc)
)

type getClusterNodesRESTAPIHandler struct {
	lock.Mutex

	db      *statedb.DB
	nodes   statedb.Table[*node.Node]
	clients map[int64]*clusterNodesClient
}

func newGetClusterNodesRESTAPIHandler(
	db *statedb.DB,
	nodes statedb.Table[*node.Node],
) daemonrestapi.GetClusterNodesHandler {
	return &getClusterNodesRESTAPIHandler{
		db:      db,
		nodes:   nodes,
		clients: map[int64]*clusterNodesClient{},
	}
}

func (h *getClusterNodesRESTAPIHandler) Handle(
	params daemonrestapi.GetClusterNodesParams,
) middleware.Responder {
	if params.ClientID == nil {
		return daemonrestapi.NewGetClusterNodesOK().WithPayload(
			&models.ClusterNodeStatus{
				Self:       nodeTypes.GetAbsoluteNodeName(),
				NodesAdded: h.nodeSnapshot(),
			},
		)
	}

	h.Lock()
	defer h.Unlock()

	clientID := *params.ClientID
	client, found := h.clients[clientID]
	if !found {
		clientID = randGen.Int64()
		if _, collision := h.clients[clientID]; collision || clientID == 0 {
			return daemonrestapi.NewGetClusterNodesOK().WithPayload(
				&models.ClusterNodeStatus{
					Self:       nodeTypes.GetAbsoluteNodeName(),
					NodesAdded: h.nodeSnapshot(),
				},
			)
		}

		var err error
		client, err = h.newClient()
		if err != nil {
			return daemonrestapi.NewGetClusterNodesOK().WithPayload(
				&models.ClusterNodeStatus{
					Self:       nodeTypes.GetAbsoluteNodeName(),
					NodesAdded: h.nodeSnapshot(),
				},
			)
		}
		h.cleanupClients()
		h.clients[clientID] = client
	}

	status := &models.ClusterNodeStatus{
		ClientID: clientID,
		Self:     nodeTypes.GetAbsoluteNodeName(),
	}
	client.drain(h.db.ReadTxn(), status)
	client.lastSync = time.Now()

	return daemonrestapi.NewGetClusterNodesOK().WithPayload(status)
}

func (h *getClusterNodesRESTAPIHandler) nodeSnapshot() []*models.NodeElement {
	txn := h.db.ReadTxn()
	nodes := make([]*models.NodeElement, 0, h.nodes.NumObjects(txn))
	for n := range h.nodes.All(txn) {
		nodes = append(nodes, n.GetModel())
	}
	return nodes
}

func (h *getClusterNodesRESTAPIHandler) newClient() (*clusterNodesClient, error) {
	wtxn := h.db.WriteTxn(h.nodes)
	changes, err := h.nodes.Changes(wtxn)
	wtxn.Commit()
	if err != nil {
		return nil, err
	}
	return &clusterNodesClient{
		changes: changes,
		nodes:   map[string]*nodeTypes.Node{},
	}, nil
}

// clientGCTimeout is the time for which clients are kept without polling.
const clientGCTimeout = 15 * time.Minute

type clusterNodesClient struct {
	lastSync time.Time
	changes  statedb.ChangeIterator[*node.Node]
	nodes    map[string]*nodeTypes.Node
}

func (c *clusterNodesClient) drain(
	txn statedb.ReadTxn,
	status *models.ClusterNodeStatus,
) {
	changes, _ := c.changes.Next(txn)
	for change := range changes {
		n := change.Object
		name := n.Fullname()
		old, found := c.nodes[name]

		if change.Deleted {
			if found {
				c.nodeDeleted(status, old)
				delete(c.nodes, name)
			}
			continue
		}

		if !found {
			c.nodeAdded(status, &n.Node)
		} else if !n.Node.DeepEqual(old) {
			c.nodeUpdated(status, old, &n.Node)
		}
		c.nodes[name] = &n.Node
	}
}

func (c *clusterNodesClient) nodeAdded(
	status *models.ClusterNodeStatus,
	n *nodeTypes.Node,
) {
	status.NodesAdded = append(status.NodesAdded, n.GetModel())
}

func (c *clusterNodesClient) nodeUpdated(
	status *models.ClusterNodeStatus,
	oldNode, newNode *nodeTypes.Node,
) {
	for i, added := range status.NodesAdded {
		if added.Name == newNode.Fullname() {
			status.NodesAdded[i] = newNode.GetModel()
			return
		}
	}

	status.NodesAdded = append(status.NodesAdded, newNode.GetModel())
	status.NodesRemoved = append(status.NodesRemoved, oldNode.GetModel())
}

func (c *clusterNodesClient) nodeDeleted(
	status *models.ClusterNodeStatus,
	n *nodeTypes.Node,
) {
	idx := slices.IndexFunc(status.NodesAdded, func(added *models.NodeElement) bool {
		return added.Name == n.Fullname()
	})
	if idx >= 0 {
		status.NodesAdded = slices.Delete(status.NodesAdded, idx, idx+1)
	} else {
		status.NodesRemoved = append(status.NodesRemoved, n.GetModel())
	}
}

func (h *getClusterNodesRESTAPIHandler) cleanupClients() {
	past := time.Now().Add(-clientGCTimeout)
	for id, client := range h.clients {
		if client.lastSync.Before(past) {
			client.changes.Close()
			delete(h.clients, id)
		}
	}
}
