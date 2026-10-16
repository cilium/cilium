// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package server

import (
	"fmt"
	"net/netip"
	"slices"
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"

	ciliumModels "github.com/cilium/cilium/api/v1/health/models"
	"github.com/cilium/cilium/api/v1/models"
	iputil "github.com/cilium/cilium/pkg/ip"
)

func makeHealthNode(nodeIdx, healthIdx int) (healthNode, netip.Addr, netip.Addr) {
	nodeIP := netip.MustParseAddr(fmt.Sprintf("192.0.2.%d", nodeIdx))
	healthIP := netip.MustParseAddr(fmt.Sprintf("10.0.2.%d", healthIdx))
	return healthNode{
		NodeElement: &models.NodeElement{
			Name: fmt.Sprintf("node-%d", nodeIdx),
			PrimaryAddress: &models.NodeAddressing{
				IPv4: &models.NodeAddressingElement{
					IP:      iputil.AddrFrom(nodeIP),
					Enabled: true,
				},
				IPv6: &models.NodeAddressingElement{
					Enabled: false,
				},
			},
			HealthEndpointAddress: &models.NodeAddressing{
				IPv4: &models.NodeAddressingElement{
					IP:      iputil.AddrFrom(healthIP),
					Enabled: true,
				},
				IPv6: &models.NodeAddressingElement{
					Enabled: false,
				},
			},
		},
	}, nodeIP, healthIP
}

func makeHealthNodeNil(nodeIdx, healthIdx int) (healthNode, netip.Addr, netip.Addr) {
	nodeIP := netip.MustParseAddr(fmt.Sprintf("192.0.2.%d", nodeIdx))
	healthIP := netip.MustParseAddr(fmt.Sprintf("10.0.2.%d", healthIdx))
	return healthNode{
		NodeElement: &models.NodeElement{
			Name:           fmt.Sprintf("node-%d", nodeIdx),
			PrimaryAddress: nil,
			HealthEndpointAddress: &models.NodeAddressing{
				IPv4: &models.NodeAddressingElement{
					IP:      iputil.AddrFrom(healthIP),
					Enabled: true,
				},
				IPv6: &models.NodeAddressingElement{
					Enabled: false,
				},
			},
		},
	}, nodeIP, healthIP
}

func sortNodes(nodes map[string][]netip.Addr) map[string][]netip.Addr {
	for _, slice := range nodes {
		slices.SortFunc(slice, netip.Addr.Compare)
	}
	return nodes
}

func TestProbersetNodes(t *testing.T) {
	logger := hivetest.Logger(t)
	node1, node1IP, node1HealthIP := makeHealthNode(1, 1)
	newNodes := nodeMap{
		node1IP: node1,
	}

	// First up: Just create a prober with some nodes.
	prober := newProber(&Server{logger: logger}, newNodes)
	nodes := prober.getIPsByNode()
	expected := map[string][]netip.Addr{
		node1.Name: {node1IP, node1HealthIP},
	}
	require.Equal(t, sortNodes(expected), sortNodes(nodes))

	// Update the health IP and observe that it is updated.
	// Note that update consists of delete and add in setNodes().
	node1, node1IP, node1HealthIP = makeHealthNode(1, 2)
	modifiedNodes := nodeMap{
		node1IP: node1,
	}
	prober.setNodes(modifiedNodes, newNodes)
	nodes = prober.getIPsByNode()
	expected = map[string][]netip.Addr{
		node1.Name: {node1IP, node1HealthIP},
	}
	require.Equal(t, sortNodes(expected), sortNodes(nodes))

	// Remove the nodes; they shouldn't be there any more
	prober.setNodes(nil, modifiedNodes)
	nodes = prober.getIPsByNode()
	expected = map[string][]netip.Addr{}
	require.Equal(t, sortNodes(expected), sortNodes(nodes))

	// Add back two nodes
	node2, node2IP, node2HealthIP := makeHealthNode(2, 20)
	updatedNodes := nodeMap{
		node1IP: node1,
		node2IP: node2,
	}
	prober.setNodes(updatedNodes, nil)
	nodes = prober.getIPsByNode()
	expected = map[string][]netip.Addr{
		node1.Name: {node1IP, node1HealthIP},
		node2.Name: {node2IP, node2HealthIP},
	}
	require.Equal(t, sortNodes(expected), sortNodes(nodes))
	// Set result of probing before updating the nodes.
	// The result should not be deleted after node update.
	if elem, ok := prober.results[node1IP]; ok {
		elem.Icmp = &ciliumModels.ConnectivityStatus{
			Status: "Some status",
		}
	} else {
		t.Errorf("expected to find result element for node's ip %s", node1IP)
	}
	// Update node 1. Node 2 should remain unaffected.
	modifiedNodesOld := nodeMap{
		node1IP: node1,
	}
	node1, node1IP, node1HealthIP = makeHealthNode(1, 5)
	modifiedNodesNew := nodeMap{
		node1IP: node1,
	}
	prober.setNodes(modifiedNodesNew, modifiedNodesOld)
	nodes = prober.getIPsByNode()
	expected[node1.Name] = []netip.Addr{node1IP, node1HealthIP}
	require.Equal(t, sortNodes(expected), sortNodes(nodes))
	if elem, ok := prober.results[node1IP]; !ok {
		t.Errorf("expected to find result element for node's ip %s", node1IP)
	} else {
		// Check that status was not removed when updating node
		require.NotNil(t, elem.Icmp)
		require.Equal(t, "Some status", elem.Icmp.Status)
	}

	// Remove node 1. Again, Node 2 should remain.
	removedNodes := nodeMap{
		node1IP: node1,
	}
	prober.setNodes(nil, removedNodes)
	nodes = prober.getIPsByNode()
	expected = map[string][]netip.Addr{
		node2.Name: {node2IP, node2HealthIP},
	}
	require.Equal(t, sortNodes(expected), sortNodes(nodes))
	// The removed node's results are dropped along with it.
	require.NotContains(t, prober.results, node1IP)
	require.NotContains(t, prober.results, node1HealthIP)
	require.Contains(t, prober.results, node2IP)

	// check if primary node is nil (it shouldn't show up)
	node3, node3IP, node3HealthIP := makeHealthNodeNil(1, 1)

	newNodes3 := nodeMap{
		node3IP: node3,
	}
	nodes3 := newProber(&Server{logger: logger}, newNodes3).getIPsByNode()
	expected3 := map[string][]netip.Addr{
		node3.Name: {node3HealthIP},
	}
	require.Equal(t, sortNodes(expected3), sortNodes(nodes3))

	// node4 has a PrimaryAddress with IPV4 enabled but an unset IP address.
	// It should not show up in the prober.
	node4, node4IP, node4HealthIP := makeHealthNodeNil(4, 4)
	node4.PrimaryAddress = &models.NodeAddressing{
		IPv4: &models.NodeAddressingElement{
			Enabled: true,
		},
		IPv6: &models.NodeAddressingElement{
			Enabled: false,
		},
	}

	newNodes4 := nodeMap{
		node4IP: node4,
	}
	prober4 := newProber(&Server{logger: logger}, newNodes4)
	nodes4 := prober4.getIPsByNode()
	expected4 := map[string][]netip.Addr{
		node4.Name: {node4HealthIP},
	}
	require.Equal(t, sortNodes(expected4), sortNodes(nodes4))
	// The unset address gets no result, so the node reports no primary host
	// address rather than one for the zero address.
	report4 := prober4.getResults()
	require.Len(t, report4.nodes, 1)
	require.Nil(t, report4.nodes[0].Host.PrimaryAddress)
}
