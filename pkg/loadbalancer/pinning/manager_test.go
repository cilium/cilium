// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package pinning

import (
	"log/slog"
	"testing"

	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/hivetest"
	"github.com/cilium/hive/job"
	"github.com/stretchr/testify/require"
)

func TestPinningManager(t *testing.T) {
	logger := hivetest.Logger(t, hivetest.LogLevel(slog.LevelInfo))

	var jg job.Group
	h := hive.New(
		cell.Invoke(func(g job.Group) { jg = g }),
	)

	require.NoError(t, h.Start(logger, t.Context()))
	t.Cleanup(func() { h.Stop(logger, t.Context()) })

	expectedNodeCount := len(allNodes)
	expectedServiceCount := len(AllServices)

	agent1 := NewPinningManagerTestSuite(t, node1, node1Ip, jg, logger, NewLbPinMapEventStream())

	nodes1 := []NodeInfo{
		{Name: node2, Ip: node2Ip},
		{Name: node3, Ip: node3Ip},
	}

	agent1.Init(t, nodes1, expectedNodeCount, AllServices, expectedServiceCount, pinToNode)

	agent2 := NewPinningManagerTestSuite(t, node2, node2Ip, jg, logger, NewLbPinMapEventStream())
	nodes2 := []NodeInfo{
		{Name: node1, Ip: node1Ip},
		{Name: node3, Ip: node3Ip},
	}
	agent2.Init(t, nodes2, expectedNodeCount, AllServices, expectedServiceCount, pinToNode)

	agent3 := NewPinningManagerTestSuite(t, node3, node3Ip, jg, logger, NewLbPinMapEventStream())

	nodes3 := []NodeInfo{
		{Name: node1, Ip: node1Ip},
		{Name: node2, Ip: node2Ip},
	}

	agent3.Init(t, nodes3, expectedNodeCount, AllServices, expectedServiceCount, pinToNode)

	require.Equal(t, expectedNodeCount, len(agent1.manager.nodesCache))
	require.Equal(t, expectedNodeCount, len(agent2.manager.nodesCache))
	require.Equal(t, expectedNodeCount, len(agent3.manager.nodesCache))

	require.Equal(t, expectedServiceCount, len(agent1.manager.servicesCache))
	require.Equal(t, expectedServiceCount, len(agent2.manager.servicesCache))
	require.Equal(t, expectedServiceCount, len(agent3.manager.servicesCache))

	agent1.checkPinningMap(t)
	agent2.checkPinningMap(t)
	agent3.checkPinningMap(t)
}
