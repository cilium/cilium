// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package neighbordiscovery

import (
	"context"
	"maps"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/cilium/statedb"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/datapath/config"
	"github.com/cilium/cilium/pkg/datapath/neighbor"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/node/addressing"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
	"github.com/cilium/cilium/pkg/source"
)

type fakeForwardableIPManager struct {
	mu          sync.Mutex
	entries     map[netip.Addr]neighbor.ForwardableIPOwner
	insertCount int
	deleteCount int
	initialized chan struct{}
	initOnce    sync.Once
}

func newFakeForwardableIPManager() *fakeForwardableIPManager {
	return &fakeForwardableIPManager{
		entries:     map[netip.Addr]neighbor.ForwardableIPOwner{},
		initialized: make(chan struct{}),
	}
}

func (m *fakeForwardableIPManager) Insert(ip netip.Addr, owner neighbor.ForwardableIPOwner) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.entries[ip] = owner
	m.insertCount++
	return nil
}

func (m *fakeForwardableIPManager) Delete(ip netip.Addr, owner neighbor.ForwardableIPOwner) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.entries[ip] == owner {
		delete(m.entries, ip)
	}
	m.deleteCount++
	return nil
}

func (m *fakeForwardableIPManager) FinishInitializer(neighbor.ForwardableIPInitializer) {
	m.initOnce.Do(func() { close(m.initialized) })
}

func (m *fakeForwardableIPManager) snapshot() (map[netip.Addr]neighbor.ForwardableIPOwner, int, int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return maps.Clone(m.entries), m.insertCount, m.deleteCount
}

func TestNodeNeighborObserver(t *testing.T) {
	db := statedb.New()
	nodes, err := node.NewNodeTable(db)
	require.NoError(t, err)

	wtxn := db.WriteTxn(nodes)
	initialNodesDone := nodes.RegisterInitializer(wtxn, "test")
	wtxn.Commit()

	manager := newFakeForwardableIPManager()
	observer, err := newNodeNeighborObserver(
		db,
		nodes,
		manager,
		neighbor.ForwardableIPInitializer{},
	)
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	runErr := make(chan error, 1)
	initErr := make(chan error, 1)
	go func() { runErr <- observer.run(ctx, nil) }()
	go func() { initErr <- observer.finishInitialization(ctx, nil) }()

	n1 := &node.Node{
		Node: nodeTypes.Node{
			Name:    "node-1",
			Cluster: "cluster-1",
			Source:  source.CustomResource,
			IPAddresses: []nodeTypes.Address{
				{Type: addressing.NodeInternalIP, IP: net.ParseIP("10.0.0.1")},
				{Type: addressing.NodeInternalIP, IP: net.ParseIP("2001:db8::1")},
			},
		},
	}
	local := &node.Node{
		Node: nodeTypes.Node{
			Name:    "local",
			Cluster: "cluster-1",
			Source:  source.Local,
			IPAddresses: []nodeTypes.Address{
				{Type: addressing.NodeInternalIP, IP: net.ParseIP("10.0.0.2")},
			},
		},
		Local: &node.LocalNodeInfo{},
	}

	wtxn = db.WriteTxn(nodes)
	nodes.Insert(wtxn, n1)
	nodes.Insert(wtxn, local)
	wtxn.Commit()

	wantOwner := neighbor.ForwardableIPOwner{
		Type: neighbor.ForwardableIPOwnerNode,
		ID:   n1.Identity().String(),
	}
	require.Eventually(t, func() bool {
		entries, _, _ := manager.snapshot()
		return maps.Equal(entries, map[netip.Addr]neighbor.ForwardableIPOwner{
			netip.MustParseAddr("10.0.0.1"):    wantOwner,
			netip.MustParseAddr("2001:db8::1"): wantOwner,
		})
	}, time.Second, time.Millisecond)

	// Neither readiness signal is sufficient on its own.
	require.NoError(t, observer.NodeConfigurationChanged(config.Config{}))
	select {
	case <-manager.initialized:
		t.Fatal("initializer finished before the node table was initialized")
	default:
	}

	wtxn = db.WriteTxn(nodes)
	initialNodesDone(wtxn)
	wtxn.Commit()
	select {
	case <-manager.initialized:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for forwardable-IP initialization")
	}

	// An update unrelated to node IPs must not touch the forwardable-IP set.
	_, insertsBefore, deletesBefore := manager.snapshot()
	n1WithLabel := &node.Node{Node: n1.Node}
	n1WithLabel.Labels = map[string]string{"unrelated": "label"}
	wtxn = db.WriteTxn(nodes)
	nodes.Insert(wtxn, n1WithLabel)
	wtxn.Commit()
	require.Never(t, func() bool {
		_, inserts, deletes := manager.snapshot()
		return inserts != insertsBefore || deletes != deletesBefore
	}, 2*changeRateLimit, time.Millisecond)

	// Changing an address removes only the old address and inserts the new one.
	n1Updated := &node.Node{
		Node: nodeTypes.Node{
			Name:    n1.Name,
			Cluster: n1.Cluster,
			Source:  n1.Source,
			IPAddresses: []nodeTypes.Address{
				{Type: addressing.NodeInternalIP, IP: net.ParseIP("10.0.0.3")},
				{Type: addressing.NodeInternalIP, IP: net.ParseIP("2001:db8::1")},
			},
		},
	}
	wtxn = db.WriteTxn(nodes)
	nodes.Insert(wtxn, n1Updated)
	wtxn.Commit()
	require.Eventually(t, func() bool {
		entries, inserts, deletes := manager.snapshot()
		return inserts == insertsBefore+1 && deletes == deletesBefore+1 &&
			maps.Equal(entries, map[netip.Addr]neighbor.ForwardableIPOwner{
				netip.MustParseAddr("10.0.0.3"):    wantOwner,
				netip.MustParseAddr("2001:db8::1"): wantOwner,
			})
	}, time.Second, time.Millisecond)

	// Deletion uses the same clustered identity as insertion.
	wtxn = db.WriteTxn(nodes)
	nodes.Delete(wtxn, n1Updated)
	wtxn.Commit()
	require.Eventually(t, func() bool {
		entries, _, _ := manager.snapshot()
		return len(entries) == 0
	}, time.Second, time.Millisecond)

	cancel()
	require.NoError(t, <-runErr)
	require.NoError(t, <-initErr)
}
