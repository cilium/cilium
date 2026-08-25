// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ipset

import (
	"context"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/cilium/hive/cell"
	"github.com/cilium/statedb"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/node/addressing"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
)

type fakeNodeIPSetManager struct {
	mu          lock.Mutex
	v4          AddrSet
	v6          AddrSet
	initialized chan struct{}
	initOnce    sync.Once
}

func newFakeNodeIPSetManager() *fakeNodeIPSetManager {
	return &fakeNodeIPSetManager{
		v4:          AddrSet{},
		v6:          AddrSet{},
		initialized: make(chan struct{}),
	}
}

func (m *fakeNodeIPSetManager) NewInitializer() Initializer {
	return (*fakeNodeIPSetInitializer)(m)
}

func (m *fakeNodeIPSetManager) AddToIPSet(
	_ string,
	family Family,
	addrs ...netip.Addr,
) {
	m.mu.Lock()
	defer m.mu.Unlock()
	set := m.v4
	if family == INet6Family {
		set = m.v6
	}
	set.Insert(addrs...)
}

func (m *fakeNodeIPSetManager) RemoveFromIPSet(
	name string,
	addrs ...netip.Addr,
) {
	m.mu.Lock()
	defer m.mu.Unlock()
	set := m.v4
	if name == CiliumNodeIPSetV6 {
		set = m.v6
	}
	set.Delete(addrs...)
}

func (m *fakeNodeIPSetManager) has(v4, v6 []netip.Addr) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	expectedV4 := AddrSet{}
	expectedV4.Insert(v4...)
	expectedV6 := AddrSet{}
	expectedV6.Insert(v6...)
	return m.v4.Equal(expectedV4) && m.v6.Equal(expectedV6)
}

type fakeNodeIPSetInitializer fakeNodeIPSetManager

func (i *fakeNodeIPSetInitializer) InitDone() {
	m := (*fakeNodeIPSetManager)(i)
	m.initOnce.Do(func() { close(m.initialized) })
}

func TestNodeIPSetSync(t *testing.T) {
	db := statedb.New()
	nodes, err := node.NewNodeTable(db)
	require.NoError(t, err)

	wtxn := db.WriteTxn(nodes)
	initDone := nodes.RegisterInitializer(wtxn, "test")
	wtxn.Commit()

	n1 := testNode("node-1",
		testAddress(addressing.NodeInternalIP, "10.0.0.1"),
		testAddress(addressing.NodeInternalIP, "10.0.0.2"),
		testAddress(addressing.NodeInternalIP, "2001:db8::1"),
		testAddress(addressing.NodeCiliumInternalIP, "192.0.2.1"),
	)
	n2 := testNode(
		"node-2",
		testAddress(addressing.NodeInternalIP, "10.0.0.2"),
	)
	insertNode(t, db, nodes, n1)
	insertNode(t, db, nodes, n2)

	manager := newFakeNodeIPSetManager()
	syncer := &nodeIPSetSync{
		db:          db,
		nodes:       nodes,
		manager:     manager,
		initializer: manager.NewInitializer(),
		v4:          AddrSet{},
		v6:          AddrSet{},
	}
	health, _ := cell.NewSimpleHealth()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- syncer.run(ctx, health) }()

	select {
	case <-manager.initialized:
		t.Fatal("IPSet initialized before the node table")
	case <-time.After(20 * time.Millisecond):
	}

	wtxn = db.WriteTxn(nodes)
	initDone(wtxn)
	wtxn.Commit()

	select {
	case <-manager.initialized:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for IPSet initialization")
	}
	require.Eventually(t, func() bool {
		return manager.has(
			[]netip.Addr{
				netip.MustParseAddr("10.0.0.1"),
				netip.MustParseAddr("10.0.0.2"),
			},
			[]netip.Addr{netip.MustParseAddr("2001:db8::1")},
		)
	}, time.Second, 10*time.Millisecond)

	deleteNode(t, db, nodes, n1)
	require.Eventually(t, func() bool {
		return manager.has(
			[]netip.Addr{netip.MustParseAddr("10.0.0.2")},
			nil,
		)
	}, time.Second, 10*time.Millisecond)

	deleteNode(t, db, nodes, n2)
	require.Eventually(t, func() bool {
		return manager.has(nil, nil)
	}, 2*nodeIPSetSyncInterval, 10*time.Millisecond)

	cancel()
	require.NoError(t, <-done)
}

func TestNodeIPSetSyncFilter(t *testing.T) {
	db := statedb.New()
	nodes, err := node.NewNodeTable(db)
	require.NoError(t, err)

	insertNode(t, db, nodes, testNode("included",
		testAddress(addressing.NodeInternalIP, "10.0.0.1"),
		testAddress(addressing.NodeInternalIP, "2001:db8::1"),
	))
	insertNode(t, db, nodes, testNode("excluded",
		testAddress(addressing.NodeInternalIP, "10.0.0.2"),
		testAddress(addressing.NodeInternalIP, "2001:db8::2"),
	))

	manager := newFakeNodeIPSetManager()
	syncer := &nodeIPSetSync{
		manager: manager,
		v4:      AddrSet{},
		v6:      AddrSet{},
		filterFn: func(n *nodeTypes.Node) bool {
			return n.Name == "excluded"
		},
	}
	syncer.update(nodes.All(db.ReadTxn()))

	require.True(t, manager.has(
		[]netip.Addr{netip.MustParseAddr("10.0.0.1")},
		[]netip.Addr{netip.MustParseAddr("2001:db8::1")},
	))
}

func testNode(name string, addresses ...nodeTypes.Address) *node.Node {
	return &node.Node{Node: nodeTypes.Node{
		Name:        name,
		IPAddresses: addresses,
	}}
}

func testAddress(addressType addressing.AddressType, ip string) nodeTypes.Address {
	return nodeTypes.Address{Type: addressType, IP: net.ParseIP(ip)}
}

func insertNode(
	t testing.TB,
	db *statedb.DB,
	nodes statedb.RWTable[*node.Node],
	n *node.Node,
) {
	t.Helper()
	txn := db.WriteTxn(nodes)
	_, _, err := nodes.Insert(txn, n)
	require.NoError(t, err)
	txn.Commit()
}

func deleteNode(
	t testing.TB,
	db *statedb.DB,
	nodes statedb.RWTable[*node.Node],
	n *node.Node,
) {
	t.Helper()
	txn := db.WriteTxn(nodes)
	_, _, err := nodes.Delete(txn, n)
	require.NoError(t, err)
	txn.Commit()
}
