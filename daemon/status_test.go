// Copyright 2016-2019 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// +build !privileged_tests

package main

import (
	"math/rand"
	"time"

	"github.com/cilium/cilium/api/v1/models"
	. "github.com/cilium/cilium/api/v1/server/restapi/daemon"
	"github.com/cilium/cilium/pkg/checker"
	"github.com/cilium/cilium/pkg/datapath/fake"
	"github.com/cilium/cilium/pkg/mtu"
	"github.com/cilium/cilium/pkg/node/manager"
	"github.com/cilium/cilium/pkg/nodediscovery"
	"github.com/cilium/cilium/pkg/option"
	cnitypes "github.com/cilium/cilium/plugins/cilium-cni/types"

	"github.com/go-openapi/runtime/middleware"
	. "gopkg.in/check.v1"
)

type GetNodesSuite struct {
}

var _ = Suite(&GetNodesSuite{})

var nm *manager.Manager

func (g *GetNodesSuite) SetUpTest(c *C) {
	option.Config.IPv4ServiceRange = AutoCIDR
	option.Config.IPv6ServiceRange = AutoCIDR
}

func (g *GetNodesSuite) SetUpSuite(c *C) {
	var err error
	nm, err = manager.NewManager("", fake.NewNodeHandler())
	c.Assert(err, IsNil)
}

func (g *GetNodesSuite) Test_getNodesHandle(c *C) {
	// Set seed so we can have the same pseudorandom client IDs.
	// The seed is set to 0 for each unit test.
	rand.Seed(0)
	const numberOfClients = 10

	clientIDs := make([]int64, 0, numberOfClients)
	for i := 0; i < numberOfClients; i++ {
		clientIDs = append(clientIDs, rand.Int63())
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
				nodeDiscovery := nodediscovery.NewNodeDiscovery(nm, mtu.NewConfiguration(0, false, false, 0), &cnitypes.NetConf{})
				nodeDiscovery.LocalNode.Name = "foo"
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
					Self:     "foo",
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
				nodeDiscovery := nodediscovery.NewNodeDiscovery(nm, mtu.NewConfiguration(0, false, false, 0), &cnitypes.NetConf{})
				nodeDiscovery.LocalNode.Name = "foo"
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
								Self:     "foo",
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
								Self:     "foo",
							},
						},
					},
					responder: &GetClusterNodesOK{
						Payload: &models.ClusterNodeStatus{
							ClientID: clientIDs[0],
							Self:     "foo",
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
				nodeDiscovery := nodediscovery.NewNodeDiscovery(nm, mtu.NewConfiguration(0, false, false, 0), &cnitypes.NetConf{})
				nodeDiscovery.LocalNode.Name = "foo"
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
								Self:     "foo",
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
								Self:     "foo",
							},
						},
					},
					responder: &GetClusterNodesOK{
						Payload: &models.ClusterNodeStatus{
							ClientID: clientIDs[0],
							Self:     "foo",
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
				nodeDiscovery := nodediscovery.NewNodeDiscovery(nm, mtu.NewConfiguration(0, false, false, 0), &cnitypes.NetConf{})
				nodeDiscovery.LocalNode.Name = "foo"
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
								Self:     "foo",
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
								Self:     "foo",
							},
						},
					},
					responder: &GetClusterNodesOK{
						Payload: &models.ClusterNodeStatus{
							ClientID: clientIDs[0],
							Self:     "foo",
						},
					},
				}
			},
		},
		{
			name: "retrieve nodes for a new client, however the randomizer allocated an existing clientID, so we should return a empty clientID",
			setupArgs: func() args {
				nodeDiscovery := nodediscovery.NewNodeDiscovery(nm, mtu.NewConfiguration(0, false, false, 0), &cnitypes.NetConf{})
				nodeDiscovery.LocalNode.Name = "foo"
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
								Self:     "foo",
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
								Self:     "foo",
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
							Self: "foo",
						},
					},
				}
			},
		},
		{
			name: "retrieve nodes for a client that does not want to have diffs, leave all other stored clients alone",
			setupArgs: func() args {
				nodeDiscovery := nodediscovery.NewNodeDiscovery(nm, mtu.NewConfiguration(0, false, false, 0), &cnitypes.NetConf{})
				nodeDiscovery.LocalNode.Name = "foo"
				return args{
					params: GetClusterNodesParams{},
					daemon: &Daemon{
						nodeDiscovery: nodeDiscovery,
					},
					clients: map[int64]*clusterNodesClient{
						clientIDs[0]: {
							ClusterNodeStatus: &models.ClusterNodeStatus{
								ClientID: clientIDs[0],
								Self:     "foo",
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
								Self:     "foo",
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
							Self: "foo",
						},
					},
				}
			},
		},
	}

	for _, tt := range tests {
		c.Log(tt.name)
		rand.Seed(0)
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
				nodeDiscovery: nodediscovery.NewNodeDiscovery(nm, mtu.NewConfiguration(0, false, false, 0), &cnitypes.NetConf{}),
			},
		}
		h.cleanupClients()
		c.Assert(h.clients, checker.DeepEquals, want.clients)
	}
}
