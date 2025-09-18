// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package server

import (
	"bytes"
	"fmt"
	"net"
	"sort"
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"

	ciliumModels "github.com/cilium/cilium/api/v1/health/models"
	"github.com/cilium/cilium/api/v1/models"
)

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

func makeHealthNodeNil(nodeIdx, healthIdx int) (healthNode, net.IP, net.IP) {
	nodeIP := fmt.Sprintf("192.0.2.%d", nodeIdx)
	healthIP := fmt.Sprintf("10.0.2.%d", healthIdx)
	return healthNode{
		NodeElement: &models.NodeElement{
			Name:           fmt.Sprintf("node-%d", nodeIdx),
			PrimaryAddress: nil,
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

func TestProbersetNodes(t *testing.T) {
	logger := hivetest.Logger(t)
	node1, node1IP, node1HealthIP := makeHealthNode(1, 1)
	newNodes := nodeMap{
		ipString(node1.Name): node1,
	}

	// First up: Just create a prober with some nodes.
	prober := newProber(&Server{logger: logger}, newNodes)
	nodes := prober.getIPsByNode()
	expected := map[string][]*net.IPAddr{
		node1.Name: {{
			IP: node1IP,
		}, {
			IP: node1HealthIP,
		}},
	}
	require.Equal(t, sortNodes(expected), sortNodes(nodes))

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
	require.Equal(t, sortNodes(expected), sortNodes(nodes))

	// Remove the nodes; they shouldn't be there any more
	prober.setNodes(nil, modifiedNodes)
	nodes = prober.getIPsByNode()
	expected = map[string][]*net.IPAddr{}
	require.Equal(t, sortNodes(expected), sortNodes(nodes))

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
	require.Equal(t, sortNodes(expected), sortNodes(nodes))
	// Set result of probing before updating the nodes.
	// The result should not be deleted after node update.
	if elem, ok := prober.results[ipString(node1.NodeElement.PrimaryAddress.IPV4.IP)]; ok {
		elem.Icmp = &ciliumModels.ConnectivityStatus{
			Status: "Some status",
		}
	} else {
		t.Errorf("expected to find result element for node's ip %s", node1.NodeElement.PrimaryAddress.IPV4.IP)
	}
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
	require.Equal(t, sortNodes(expected), sortNodes(nodes))
	if elem, ok := prober.results[ipString(node1.NodeElement.PrimaryAddress.IPV4.IP)]; !ok {
		t.Errorf("expected to find result element for node's ip %s", node1.NodeElement.PrimaryAddress.IPV4.IP)
	} else {
		// Check that status was not removed when updating node
		require.NotNil(t, elem.Icmp)
		require.Equal(t, "Some status", elem.Icmp.Status)
	}

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
	require.Equal(t, sortNodes(expected), sortNodes(nodes))

	// check if primary node is nil (it shouldn't show up)
	node3, _, node3HealthIP := makeHealthNodeNil(1, 1)

	newNodes3 := nodeMap{
		ipString(node3.Name): node3,
	}
	nodes3 := newProber(&Server{logger: logger}, newNodes3).getIPsByNode()
	expected3 := map[string][]*net.IPAddr{
		node3.Name: {{
			IP: node3HealthIP,
		}},
	}
	require.Equal(t, sortNodes(expected3), sortNodes(nodes3))

	// node4 has a PrimaryAddress with IPV4 enabled but an empty IP address.
	// It should not show up in the prober.
	node4, _, node4HealthIP := makeHealthNodeNil(4, 4)
	node4.PrimaryAddress = &models.NodeAddressing{
		IPV4: &models.NodeAddressingElement{
			IP:      "",
			Enabled: true,
		},
		IPV6: &models.NodeAddressingElement{
			Enabled: false,
		},
	}

	newNodes4 := nodeMap{
		ipString(node4.Name): node4,
	}
	prober4 := newProber(&Server{logger: logger}, newNodes4)
	nodes4 := prober4.getIPsByNode()
	expected4 := map[string][]*net.IPAddr{
		node4.Name: {{
			IP: node4HealthIP,
		}},
	}
	require.Equal(t, sortNodes(expected4), sortNodes(nodes4))
}
