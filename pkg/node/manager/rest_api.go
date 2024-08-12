// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package manager

import (
	"context"
	"math/rand/v2"

	"github.com/go-openapi/runtime/middleware"

	"github.com/cilium/cilium/api/v1/models"
	daemonrestapi "github.com/cilium/cilium/api/v1/server/restapi/daemon"
	datapath "github.com/cilium/cilium/pkg/datapath/types"
	"github.com/cilium/cilium/pkg/lock"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
	"github.com/cilium/cilium/pkg/time"
)

var (
	// randSrc is a source of pseudo-random numbers. It is seeded to the current time in
	// nanoseconds by default but can be reseeded in tests so they are deterministic.
	randSrc = rand.NewPCG(uint64(time.Now().UnixNano()), 0)
	randGen = rand.New(randSrc)
)

type getClusterNodesRestApiHandler struct {
	// mutex to protect the clients map against concurrent access
	lock.RWMutex

	nodeManager NodeManager

	// clients maps a client ID to a clusterNodesClient
	clients map[int64]*clusterNodesClient
}

func newGetClusterNodesRestAPIHandler(nodeManager NodeManager) daemonrestapi.GetClusterNodesHandler {
	return &getClusterNodesRestApiHandler{
		nodeManager: nodeManager,
		clients:     map[int64]*clusterNodesClient{},
	}
}

func (h *getClusterNodesRestApiHandler) Handle(params daemonrestapi.GetClusterNodesParams) middleware.Responder {
	var cns *models.ClusterNodeStatus
	// If ClientID is not set then we send all nodes, otherwise we will store
	// the client ID in the list of clients and we subscribe this new client
	// to the list of clients.
	if params.ClientID == nil {
		ns := h.getNodeStatus()
		cns = &models.ClusterNodeStatus{
			Self:       ns.Self,
			NodesAdded: ns.Nodes,
		}
		return daemonrestapi.NewGetClusterNodesOK().WithPayload(cns)
	}

	h.Lock()
	defer h.Unlock()

	var clientID int64
	c, exists := h.clients[*params.ClientID]
	if exists {
		clientID = *params.ClientID
	} else {
		clientID = randGen.Int64()
		// make sure we haven't allocated an existing client ID nor the
		// randomizer has allocated ID 0, if we have then we will return
		// clientID 0.
		_, exists := h.clients[clientID]
		if exists || clientID == 0 {
			ns := h.getNodeStatus()
			cns = &models.ClusterNodeStatus{
				ClientID:   0,
				Self:       ns.Self,
				NodesAdded: ns.Nodes,
			}
			return daemonrestapi.NewGetClusterNodesOK().WithPayload(cns)
		}
		c = &clusterNodesClient{
			lastSync: time.Now(),
			ClusterNodeStatus: &models.ClusterNodeStatus{
				ClientID: clientID,
				Self:     nodeTypes.GetAbsoluteNodeName(),
			},
		}
		h.nodeManager.Subscribe(c)

		// Clean up other clients before adding a new one
		h.cleanupClients()
		h.clients[clientID] = c
	}
	c.Lock()
	// Copy the ClusterNodeStatus to the response
	cns = c.ClusterNodeStatus
	// Store a new ClusterNodeStatus to reset the list of nodes
	// added / removed.
	c.ClusterNodeStatus = &models.ClusterNodeStatus{
		ClientID: clientID,
		Self:     nodeTypes.GetAbsoluteNodeName(),
	}
	c.lastSync = time.Now()
	c.Unlock()

	return daemonrestapi.NewGetClusterNodesOK().WithPayload(cns)
}

func (d *getClusterNodesRestApiHandler) getNodeStatus() *models.ClusterStatus {
	clusterStatus := models.ClusterStatus{
		Self: nodeTypes.GetAbsoluteNodeName(),
	}
	for _, node := range d.nodeManager.GetNodes() {
		clusterStatus.Nodes = append(clusterStatus.Nodes, node.GetModel())
	}
	return &clusterStatus
}

// clientGCTimeout is the time for which the clients are kept. After timeout
// is reached, clients will be cleaned up.
const clientGCTimeout = 15 * time.Minute

type clusterNodesClient struct {
	// mutex to protect the client against concurrent access
	lock.RWMutex
	lastSync time.Time
	*models.ClusterNodeStatus
}

func (c *clusterNodesClient) Name() string {
	return "cluster-node"
}

func (c *clusterNodesClient) NodeAdd(newNode nodeTypes.Node) error {
	c.Lock()
	c.NodesAdded = append(c.NodesAdded, newNode.GetModel())
	c.Unlock()
	return nil
}

func (c *clusterNodesClient) NodeUpdate(oldNode, newNode nodeTypes.Node) error {
	c.Lock()
	defer c.Unlock()

	// If the node is on the added list, just update it
	for i, added := range c.NodesAdded {
		if added.Name == newNode.Fullname() {
			c.NodesAdded[i] = newNode.GetModel()
			return nil
		}
	}

	// otherwise, add the new node and remove the old one
	c.NodesAdded = append(c.NodesAdded, newNode.GetModel())
	c.NodesRemoved = append(c.NodesRemoved, oldNode.GetModel())
	return nil
}

func (c *clusterNodesClient) NodeDelete(node nodeTypes.Node) error {
	c.Lock()
	// If the node was added/updated and removed before the clusterNodesClient
	// was aware of it then we can safely remove it from the list of added
	// nodes and not set it in the list of removed nodes.
	found := -1
	for i, added := range c.NodesAdded {
		if added.Name == node.Fullname() {
			found = i
		}
	}
	if found != -1 {
		c.NodesAdded = append(c.NodesAdded[:found], c.NodesAdded[found+1:]...)
	} else {
		c.NodesRemoved = append(c.NodesRemoved, node.GetModel())
	}
	c.Unlock()
	return nil
}

func (c *clusterNodesClient) AllNodeValidateImplementation() {
}

func (c *clusterNodesClient) NodeValidateImplementation(node nodeTypes.Node) error {
	// no-op
	return nil
}

func (c *clusterNodesClient) NodeConfigurationChanged(config datapath.LocalNodeConfiguration) error {
	// no-op
	return nil
}

func (c *clusterNodesClient) NodeNeighDiscoveryEnabled() bool {
	// no-op
	return false
}

func (c *clusterNodesClient) NodeNeighborRefresh(ctx context.Context, node nodeTypes.Node, refresh bool) error {
	return nil
}

func (c *clusterNodesClient) NodeCleanNeighbors(migrateOnly bool) {
	// no-op
}

func (c *clusterNodesClient) GetNodeIP(_ uint16) string {
	// no-op
	return ""
}

func (c *clusterNodesClient) DumpNodeIDs() []*models.NodeID {
	// no-op
	return nil
}

func (c *clusterNodesClient) RestoreNodeIDs() {
	// no-op
}

func (h *getClusterNodesRestApiHandler) cleanupClients() {
	past := time.Now().Add(-clientGCTimeout)
	for k, v := range h.clients {
		if v.lastSync.Before(past) {
			h.nodeManager.Unsubscribe(v)
			delete(h.clients, k)
		}
	}
}
