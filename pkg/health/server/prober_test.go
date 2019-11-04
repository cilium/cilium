// Copyright 2019 Authors of Cilium
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

package server

import (
	"bytes"
	"fmt"
	"net"
	"sort"
	"testing"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/checker"

	"gopkg.in/check.v1"
)

func Test(t *testing.T) { check.TestingT(t) }

type HealthServerTestSuite struct{}

var _ = check.Suite(&HealthServerTestSuite{})

func makeHealthNode(nodeIdx, healthIdx int) (healthNode, net.IP, net.IP) {
	nodeIP := fmt.Sprintf("192.0.2.%d", nodeIdx)
	healthIP := fmt.Sprintf("10.0.2.%d", healthIdx)
	return healthNode{
		NodeElement: &models.NodeElement{
			Name: fmt.Sprintf("node-%d", nodeIdx),
			PrimaryAddress: &models.NodeAddressing{
				IPV4: &models.NodeAddressingElement{
					IP:      nodeIP,
					Enabled: true,
				},
				IPV6: &models.NodeAddressingElement{
					Enabled: false,
				},
			},
			HealthEndpointAddress: &models.NodeAddressing{
				IPV4: &models.NodeAddressingElement{
					IP:      healthIP,
					Enabled: true,
				},
				IPV6: &models.NodeAddressingElement{
					Enabled: false,
				},
			},
		},
	}, net.ParseIP(nodeIP), net.ParseIP(healthIP)
}

func sortNodes(nodes map[string][]*net.IPAddr) map[string][]*net.IPAddr {
	for _, slice := range nodes {
		sort.Slice(slice, func(i, j int) bool {
			iLength := len(slice[i].IP)
			jLength := len(slice[j].IP)
			if iLength == jLength {
				return bytes.Compare(slice[i].IP, slice[j].IP) < 0
			}
			return iLength < jLength
		})
	}
	return nodes
}

func (s *HealthServerTestSuite) TestProbersetNodes(c *check.C) {
	node1, node1IP, node1HealthIP := makeHealthNode(1, 1)
	newNodes := nodeMap{
		ipString(node1.Name): node1,
	}

	// First up: Just create a prober with some nodes.
	prober := newProber(&Server{}, newNodes)
	nodes := prober.getIPsByNode()
	expected := map[string][]*net.IPAddr{
		node1.Name: {{
			IP: node1IP,
		}, {
			IP: node1HealthIP,
		}},
	}
	c.Assert(sortNodes(nodes), checker.DeepEquals, sortNodes(expected))

	// Update the health IP and observe that it is updated.
	// Note that update consists of delete and add in setNodes().
	node1, node1IP, node1HealthIP = makeHealthNode(1, 2)
	modifiedNodes := nodeMap{
		ipString(node1.Name): node1,
	}
	prober.setNodes(modifiedNodes, newNodes)
	nodes = prober.getIPsByNode()
	expected = map[string][]*net.IPAddr{
		node1.Name: {{
			IP: node1IP,
		}, {
			IP: node1HealthIP,
		}},
	}
	c.Assert(sortNodes(nodes), checker.DeepEquals, sortNodes(expected))

	// Remove the nodes; they shouldn't be there any more
	prober.setNodes(nil, modifiedNodes)
	nodes = prober.getIPsByNode()
	expected = map[string][]*net.IPAddr{}
	c.Assert(sortNodes(nodes), checker.DeepEquals, sortNodes(expected))

	// Add back two nodes
	node2, node2IP, node2HealthIP := makeHealthNode(2, 20)
	updatedNodes := nodeMap{
		ipString(node1.Name): node1,
		ipString(node2.Name): node2,
	}
	prober.setNodes(updatedNodes, nil)
	nodes = prober.getIPsByNode()
	expected = map[string][]*net.IPAddr{
		node1.Name: {{
			IP: node1IP,
		}, {
			IP: node1HealthIP,
		}},
		node2.Name: {{
			IP: node2IP,
		}, {
			IP: node2HealthIP,
		}},
	}
	c.Assert(sortNodes(nodes), checker.DeepEquals, sortNodes(expected))

	// Update node 1. Node 2 should remain unaffected.
	modifiedNodesOld := nodeMap{
		ipString(node1.Name): node1,
	}
	node1, node1IP, node1HealthIP = makeHealthNode(1, 5)
	modifiedNodesNew := nodeMap{
		ipString(node1.Name): node1,
	}
	prober.setNodes(modifiedNodesNew, modifiedNodesOld)
	nodes = prober.getIPsByNode()
	expected[node1.Name] = []*net.IPAddr{{
		IP: node1IP,
	}, {
		IP: node1HealthIP,
	}}
	c.Assert(sortNodes(nodes), checker.DeepEquals, sortNodes(expected))

	// Remove node 1. Again, Node 2 should remain.
	removedNodes := nodeMap{
		ipString(node1.Name): node1,
	}
	prober.setNodes(nil, removedNodes)
	nodes = prober.getIPsByNode()
	expected = map[string][]*net.IPAddr{
		node2.Name: {{
			IP: node2IP,
		}, {
			IP: node2HealthIP,
		}},
	}
	c.Assert(sortNodes(nodes), checker.DeepEquals, sortNodes(expected))
}
