// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"time"

	. "github.com/cilium/checkmate"
	"github.com/go-openapi/runtime/middleware"

	"github.com/cilium/cilium/api/v1/models"
	. "github.com/cilium/cilium/api/v1/server/restapi/daemon"
	"github.com/cilium/cilium/pkg/checker"
	"github.com/cilium/cilium/pkg/mtu"
	"github.com/cilium/cilium/pkg/node/manager"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
	"github.com/cilium/cilium/pkg/nodediscovery"
	"github.com/cilium/cilium/pkg/option"
	fakeConfig "github.com/cilium/cilium/pkg/option/fake"
	cnitypes "github.com/cilium/cilium/plugins/cilium-cni/types"
)

type GetNodesSuite struct {
}

var _ = Suite(&GetNodesSuite{})

var nm manager.NodeManager

func (g *GetNodesSuite) SetUpTest(c *C) {
	option.Config.IPv4ServiceRange = AutoCIDR
	option.Config.IPv6ServiceRange = AutoCIDR
}

func (g *GetNodesSuite) SetUpSuite(c *C) {
	var err error
	nm, err = manager.New("", &fakeConfig.Config{}, nil)
	c.Assert(err, IsNil)
}

func (g *GetNodesSuite) Test_getNodesHandle(c *C) {
	// Set seed so we can have the same pseudorandom client IDs.
	// The seed is set to 0 for each unit test.
	randGen.Seed(0)
	const numberOfClients = 10

	clientIDs := make([]int64, 0, numberOfClients)
	for i := 0; i < numberOfClients; i++ {
		clientIDs = append(clientIDs, randGen.Int63())
	}

	var zero int64
	type args struct {
		params  GetClusterNodesParams
		clients map[int64]*clusterNodesClient
		daemon  *Daemon
	}
	type want struct {
		clients   map[int64]*clusterNodesClient
		responder *GetClusterNodesOK
	}
	tests := []struct {
		name        string
		setupArgs   func() args
		setupWanted func() want
	}{
		{
			name: "create a client ID and store it locally",
			setupArgs: func() args {
				nodeDiscovery := nodediscovery.NewNodeDiscovery(nm, nil, mtu.NewConfiguration(0, false, false, false, 0, nil), &cnitypes.NetConf{})
				return args{
					params: GetClusterNodesParams{
						ClientID: &zero,
					},
					daemon: &Daemon{
						nodeDiscovery: nodeDiscovery,
					},
					clients: map[int64]*clusterNodesClient{},
				}
			},
			setupWanted: func() want {
				m := &models.ClusterNodeStatus{
					ClientID: clientIDs[0],
					Self:     nodeTypes.GetAbsoluteNodeName(),
				}
				return want{
					clients: map[int64]*clusterNodesClient{
						clientIDs[0]: {
							ClusterNodeStatus: m,
						},
					},
					responder: &GetClusterNodesOK{
						Payload: m,
					},
				}
			},
		},
		{
			name: "retrieve nodes diff from a client that was already present",
			setupArgs: func() args {
				nodeDiscovery := nodediscovery.NewNodeDiscovery(nm, nil, mtu.NewConfiguration(0, false, false, false, 0, nil), &cnitypes.NetConf{})
				return args{
					params: GetClusterNodesParams{
						ClientID: &clientIDs[0],
					},
					daemon: &Daemon{
						nodeDiscovery: nodeDiscovery,
					},
					clients: map[int64]*clusterNodesClient{
						clientIDs[0]: {
							ClusterNodeStatus: &models.ClusterNodeStatus{
								ClientID: clientIDs[0],
								Self:     nodeTypes.GetAbsoluteNodeName(),
								NodesAdded: []*models.NodeElement{
									{
										Name: "random-node-added",
									},
								},
							},
						},
					},
				}
			},
			setupWanted: func() want {
				return want{
					// let's not forget once the server sends the diff to the
					// client, the slice of nodes added and removed gets cleaned
					// up
					clients: map[int64]*clusterNodesClient{
						clientIDs[0]: {
							ClusterNodeStatus: &models.ClusterNodeStatus{
								ClientID: clientIDs[0],
								Self:     nodeTypes.GetAbsoluteNodeName(),
							},
						},
					},
					responder: &GetClusterNodesOK{
						Payload: &models.ClusterNodeStatus{
							ClientID: clientIDs[0],
							Self:     nodeTypes.GetAbsoluteNodeName(),
							NodesAdded: []*models.NodeElement{
								{
									Name: "random-node-added",
								},
							},
						},
					},
				}
			},
		},
		{
			name: "retrieve nodes from an expired client, it should be ok because the clean up only happens when on insertion",
			setupArgs: func() args {
				nodeDiscovery := nodediscovery.NewNodeDiscovery(nm, nil, mtu.NewConfiguration(0, false, false, false, 0, nil), &cnitypes.NetConf{})
				return args{
					params: GetClusterNodesParams{
						ClientID: &clientIDs[0],
					},
					daemon: &Daemon{
						nodeDiscovery: nodeDiscovery,
					},
					clients: map[int64]*clusterNodesClient{
						clientIDs[0]: {
							lastSync: time.Now().Add(-clientGCTimeout),
							ClusterNodeStatus: &models.ClusterNodeStatus{
								ClientID: clientIDs[0],
								Self:     nodeTypes.GetAbsoluteNodeName(),
								NodesAdded: []*models.NodeElement{
									{
										Name: "random-node-added",
									},
								},
							},
						},
					},
				}
			},
			setupWanted: func() want {
				return want{
					// let's not forget once the server sends the diff to the
					// client, the slice of nodes added and removed gets cleaned
					// up
					clients: map[int64]*clusterNodesClient{
						clientIDs[0]: {
							ClusterNodeStatus: &models.ClusterNodeStatus{
								ClientID: clientIDs[0],
								Self:     nodeTypes.GetAbsoluteNodeName(),
							},
						},
					},
					responder: &GetClusterNodesOK{
						Payload: &models.ClusterNodeStatus{
							ClientID: clientIDs[0],
							Self:     nodeTypes.GetAbsoluteNodeName(),
							NodesAdded: []*models.NodeElement{
								{
									Name: "random-node-added",
								},
							},
						},
					},
				}
			},
		},
		{
			name: "retrieve nodes for a new client, the expired client should be deleted",
			setupArgs: func() args {
				nodeDiscovery := nodediscovery.NewNodeDiscovery(nm, nil, mtu.NewConfiguration(0, false, false, false, 0, nil), &cnitypes.NetConf{})
				return args{
					params: GetClusterNodesParams{
						ClientID: &zero,
					},
					daemon: &Daemon{
						nodeDiscovery: nodeDiscovery,
					},
					clients: map[int64]*clusterNodesClient{
						clientIDs[numberOfClients-1]: {
							lastSync: time.Now().Add(-clientGCTimeout),
							ClusterNodeStatus: &models.ClusterNodeStatus{
								ClientID: clientIDs[numberOfClients-1],
								Self:     nodeTypes.GetAbsoluteNodeName(),
								NodesAdded: []*models.NodeElement{
									{
										Name: "random-node-added",
									},
								},
							},
						},
					},
				}
			},
			setupWanted: func() want {
				return want{
					// let's not forget once the server sends the diff to the
					// client, the slice of nodes added and removed gets cleaned
					// up
					clients: map[int64]*clusterNodesClient{
						clientIDs[0]: {
							ClusterNodeStatus: &models.ClusterNodeStatus{
								ClientID: clientIDs[0],
								Self:     nodeTypes.GetAbsoluteNodeName(),
							},
						},
					},
					responder: &GetClusterNodesOK{
						Payload: &models.ClusterNodeStatus{
							ClientID: clientIDs[0],
							Self:     nodeTypes.GetAbsoluteNodeName(),
						},
					},
				}
			},
		},
		{
			name: "retrieve nodes for a new client, however the randomizer allocated an existing clientID, so we should return a empty clientID",
			setupArgs: func() args {
				nodeDiscovery := nodediscovery.NewNodeDiscovery(nm, nil, mtu.NewConfiguration(0, false, false, false, 0, nil), &cnitypes.NetConf{})
				return args{
					params: GetClusterNodesParams{
						ClientID: &zero,
					},
					daemon: &Daemon{
						nodeDiscovery: nodeDiscovery,
					},
					clients: map[int64]*clusterNodesClient{
						clientIDs[0]: {
							ClusterNodeStatus: &models.ClusterNodeStatus{
								ClientID: clientIDs[0],
								Self:     nodeTypes.GetAbsoluteNodeName(),
								NodesAdded: []*models.NodeElement{
									{
										Name: "random-node-added",
									},
								},
							},
						},
					},
				}
			},
			setupWanted: func() want {
				return want{
					clients: map[int64]*clusterNodesClient{
						clientIDs[0]: {
							ClusterNodeStatus: &models.ClusterNodeStatus{
								ClientID: clientIDs[0],
								Self:     nodeTypes.GetAbsoluteNodeName(),
								NodesAdded: []*models.NodeElement{
									{
										Name: "random-node-added",
									},
								},
							},
						},
					},
					responder: &GetClusterNodesOK{
						Payload: &models.ClusterNodeStatus{
							Self: nodeTypes.GetAbsoluteNodeName(),
						},
					},
				}
			},
		},
		{
			name: "retrieve nodes for a client that does not want to have diffs, leave all other stored clients alone",
			setupArgs: func() args {
				nodeDiscovery := nodediscovery.NewNodeDiscovery(nm, nil, mtu.NewConfiguration(0, false, false, false, 0, nil), &cnitypes.NetConf{})
				return args{
					params: GetClusterNodesParams{},
					daemon: &Daemon{
						nodeDiscovery: nodeDiscovery,
					},
					clients: map[int64]*clusterNodesClient{
						clientIDs[0]: {
							ClusterNodeStatus: &models.ClusterNodeStatus{
								ClientID: clientIDs[0],
								Self:     nodeTypes.GetAbsoluteNodeName(),
								NodesAdded: []*models.NodeElement{
									{
										Name: "random-node-added",
									},
								},
							},
						},
					},
				}
			},
			setupWanted: func() want {
				return want{
					clients: map[int64]*clusterNodesClient{
						clientIDs[0]: {
							ClusterNodeStatus: &models.ClusterNodeStatus{
								ClientID: clientIDs[0],
								Self:     nodeTypes.GetAbsoluteNodeName(),
								NodesAdded: []*models.NodeElement{
									{
										Name: "random-node-added",
									},
								},
							},
						},
					},
					responder: &GetClusterNodesOK{
						Payload: &models.ClusterNodeStatus{
							Self: nodeTypes.GetAbsoluteNodeName(),
						},
					},
				}
			},
		},
	}

	for _, tt := range tests {
		c.Log(tt.name)
		randGen.Seed(0)
		args := tt.setupArgs()
		want := tt.setupWanted()
		h := &getNodes{
			clients: args.clients,
			d:       args.daemon,
		}
		responder := h.Handle(args.params)
		c.Assert(len(h.clients), checker.DeepEquals, len(want.clients))
		for k, v := range h.clients {
			wantClient, ok := want.clients[k]
			c.Assert(ok, Equals, true)
			c.Assert(v.ClusterNodeStatus, checker.DeepEquals, wantClient.ClusterNodeStatus)
		}
		c.Assert(responder, checker.DeepEquals, middleware.Responder(want.responder))
	}
}

func (g *GetNodesSuite) Test_cleanupClients(c *C) {
	now := time.Now()
	type args struct {
		clients map[int64]*clusterNodesClient
	}
	tests := []struct {
		name        string
		setupArgs   func() args
		setupWanted func() args
	}{
		{
			name: "delete expired clients",
			setupArgs: func() args {
				return args{
					clients: map[int64]*clusterNodesClient{
						0: {
							lastSync: now.Add(-clientGCTimeout),
						},
						1: {
							lastSync: now,
						},
					},
				}
			},
			setupWanted: func() args {
				return args{
					clients: map[int64]*clusterNodesClient{
						1: {
							lastSync: now,
						},
					},
				}
			},
		},
	}

	for _, tt := range tests {
		c.Log(tt.name)
		args := tt.setupArgs()
		want := tt.setupWanted()
		h := &getNodes{
			clients: args.clients,
			d: &Daemon{
				nodeDiscovery: nodediscovery.NewNodeDiscovery(nm, nil, mtu.NewConfiguration(0, false, false, false, 0, nil), &cnitypes.NetConf{}),
			},
		}
		h.cleanupClients()
		c.Assert(h.clients, checker.DeepEquals, want.clients)
	}
}
