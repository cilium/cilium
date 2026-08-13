// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package manager

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/hivetest"
	"github.com/cilium/statedb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/datapath/tables"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/hive/health"
	"github.com/cilium/cilium/pkg/hive/health/types"
	iputil "github.com/cilium/cilium/pkg/ip"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/node/addressing"
	fakenode "github.com/cilium/cilium/pkg/node/fake"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
	"github.com/cilium/cilium/pkg/source"
)

type signalNodeHandler struct {
	EnableNodeAddEvent                    bool
	NodeAddEvent                          chan nodeTypes.Node
	NodeAddEventError                     error
	NodeUpdateEvent                       chan nodeTypes.Node
	NodeUpdateEventError                  error
	EnableNodeUpdateEvent                 bool
	NodeDeleteEvent                       chan nodeTypes.Node
	NodeDeleteEventError                  error
	EnableNodeDeleteEvent                 bool
	NodeValidateImplementationEvent       chan nodeTypes.Node
	NodeValidateImplementationEventError  error
	EnableNodeValidateImplementationEvent bool
	Stop                                  chan struct{}
}

func newSignalNodeHandler() *signalNodeHandler {
	return &signalNodeHandler{
		NodeAddEvent:                    make(chan nodeTypes.Node, 10),
		NodeUpdateEvent:                 make(chan nodeTypes.Node, 10),
		NodeDeleteEvent:                 make(chan nodeTypes.Node, 10),
		NodeValidateImplementationEvent: make(chan nodeTypes.Node, 4096),
		Stop:                            make(chan struct{}, 10),
	}
}

func (s *signalNodeHandler) Name() string {
	return "manager_test:signalNodeHandler"
}

func (n *signalNodeHandler) NodeAdd(newNode nodeTypes.Node) error {
	if n.EnableNodeAddEvent {
		n.NodeAddEvent <- newNode
	}
	return n.NodeAddEventError
}

func (n *signalNodeHandler) NodeUpdate(oldNode, newNode nodeTypes.Node) error {
	if n.EnableNodeUpdateEvent {
		n.NodeUpdateEvent <- newNode
	}
	return n.NodeUpdateEventError
}

func (n *signalNodeHandler) NodeDelete(node nodeTypes.Node) error {
	if n.EnableNodeDeleteEvent {
		n.NodeDeleteEvent <- node
	}
	return n.NodeDeleteEventError
}

func (n *signalNodeHandler) AllNodeValidateImplementation() {
}

func (n *signalNodeHandler) NodeValidateImplementation(node nodeTypes.Node) error {
	if n.EnableNodeValidateImplementationEvent {
		select {
		case <-n.Stop:
		case n.NodeValidateImplementationEvent <- node:
		}
	}
	return n.NodeValidateImplementationEventError
}

func TestNodeLifecycle(t *testing.T) {
	logger := hivetest.Logger(t)

	dp := newSignalNodeHandler()
	dp.EnableNodeAddEvent = true
	dp.EnableNodeUpdateEvent = true
	dp.EnableNodeDeleteEvent = true
	h, _ := cell.NewSimpleHealth()
	mngr, err := New(logger, NewNodeMetrics(), h, nil, nil, nil, nil)
	mngr.Subscribe(dp)
	require.NoError(t, err)

	n1 := nodeTypes.Node{
		Name: "node1", Cluster: "c1", IPAddresses: []nodeTypes.Address{
			{
				Type: addressing.NodeInternalIP,
				IP:   net.ParseIP("10.0.0.1"),
			},
		},
		Source: source.Unspec,
	}
	mngr.NodeUpdated(n1)

	select {
	case nodeEvent := <-dp.NodeAddEvent:
		require.Equal(t, n1, nodeEvent)
	case nodeEvent := <-dp.NodeUpdateEvent:
		t.Errorf("Unexpected NodeUpdate() event %#v", nodeEvent)
	case nodeEvent := <-dp.NodeDeleteEvent:
		t.Errorf("Unexpected NodeDelete() event %#v", nodeEvent)
	case <-time.After(3 * time.Second):
		t.Errorf("timeout while waiting for NodeAdd() event for node1")
	}

	n2 := nodeTypes.Node{
		Name: "node2", Cluster: "c1", IPAddresses: []nodeTypes.Address{
			{
				Type: addressing.NodeInternalIP,
				IP:   net.ParseIP("10.0.0.2"),
			},
		},
		Source: source.Unspec,
	}
	mngr.NodeUpdated(n2)

	select {
	case nodeEvent := <-dp.NodeAddEvent:
		require.Equal(t, n2, nodeEvent)
	case nodeEvent := <-dp.NodeUpdateEvent:
		t.Errorf("Unexpected NodeUpdate() event %#v", nodeEvent)
	case nodeEvent := <-dp.NodeDeleteEvent:
		t.Errorf("Unexpected NodeDelete() event %#v", nodeEvent)
	case <-time.After(3 * time.Second):
		t.Errorf("timeout while waiting for NodeUpdate() event for node2")
	}

	nodes := mngr.GetNodes()
	n, ok := nodes[n1.Identity()]
	require.True(t, ok)
	require.Equal(t, n1, n)

	mngr.NodeDeleted(n1)
	select {
	case nodeEvent := <-dp.NodeDeleteEvent:
		require.Equal(t, n1, nodeEvent)
	case nodeEvent := <-dp.NodeAddEvent:
		t.Errorf("Unexpected NodeAdd() event %#v", nodeEvent)
	case nodeEvent := <-dp.NodeUpdateEvent:
		t.Errorf("Unexpected NodeUpdate() event %#v", nodeEvent)
	case <-time.After(3 * time.Second):
		t.Errorf("timeout while waiting for NodeDelete() event for node1")
	}
	nodes = mngr.GetNodes()
	_, ok = nodes[n1.Identity()]
	require.False(t, ok)

	err = mngr.Stop(context.TODO())
	require.NoError(t, err)
}

func TestMultipleSources(t *testing.T) {
	logger := hivetest.Logger(t)

	dp := newSignalNodeHandler()
	dp.EnableNodeAddEvent = true
	dp.EnableNodeUpdateEvent = true
	dp.EnableNodeDeleteEvent = true
	h, _ := cell.NewSimpleHealth()
	mngr, err := New(logger, NewNodeMetrics(), h, nil, nil, nil, nil)
	require.NoError(t, err)
	mngr.Subscribe(dp)
	defer mngr.Stop(context.TODO())

	n1k8s := nodeTypes.Node{Name: "node1", Cluster: "c1", Source: source.Kubernetes, IPAddresses: []nodeTypes.Address{
		{
			Type: addressing.NodeInternalIP,
			IP:   net.ParseIP("10.0.0.1"),
		},
	}}
	mngr.NodeUpdated(n1k8s)
	select {
	case nodeEvent := <-dp.NodeAddEvent:
		require.Equal(t, n1k8s, nodeEvent)
	case nodeEvent := <-dp.NodeUpdateEvent:
		t.Errorf("Unexpected NodeUpdate() event %#v", nodeEvent)
	case nodeEvent := <-dp.NodeDeleteEvent:
		t.Errorf("Unexpected NodeDelete() event %#v", nodeEvent)
	case <-time.After(3 * time.Second):
		t.Errorf("timeout while waiting for NodeAdd() event for node1")
	}

	// agent can overwrite kubernetes
	n1agent := nodeTypes.Node{Name: "node1", Cluster: "c1", Source: source.Local, IPAddresses: []nodeTypes.Address{
		{
			Type: addressing.NodeInternalIP,
			IP:   net.ParseIP("10.0.0.1"),
		},
	}}
	mngr.NodeUpdated(n1agent)
	select {
	case nodeEvent := <-dp.NodeUpdateEvent:
		require.Equal(t, n1agent, nodeEvent)
	case nodeEvent := <-dp.NodeAddEvent:
		t.Errorf("Unexpected NodeAdd() event %#v", nodeEvent)
	case nodeEvent := <-dp.NodeDeleteEvent:
		t.Errorf("Unexpected NodeDelete() event %#v", nodeEvent)
	case <-time.After(3 * time.Second):
		t.Errorf("timeout while waiting for NodeUpdate() event for node1")
	}

	// kubernetes cannot overwrite local node
	mngr.NodeUpdated(n1k8s)
	select {
	case nodeEvent := <-dp.NodeAddEvent:
		t.Errorf("Unexpected NodeAdd() event %#v", nodeEvent)
	case nodeEvent := <-dp.NodeUpdateEvent:
		t.Errorf("Unexpected NodeUpdate() event %#v", nodeEvent)
	case nodeEvent := <-dp.NodeDeleteEvent:
		t.Errorf("Unexpected NodeDelete() event %#v", nodeEvent)
	case <-time.After(100 * time.Millisecond):
	}

	// delete from kubernetes, should not remove local node
	mngr.NodeDeleted(n1k8s)
	select {
	case nodeEvent := <-dp.NodeAddEvent:
		t.Errorf("Unexpected NodeAdd() event %#v", nodeEvent)
	case nodeEvent := <-dp.NodeUpdateEvent:
		t.Errorf("Unexpected NodeUpdate() event %#v", nodeEvent)
	case nodeEvent := <-dp.NodeDeleteEvent:
		t.Errorf("Unexpected NodeDelete() event %#v", nodeEvent)
	case <-time.After(100 * time.Millisecond):
	}

	mngr.NodeDeleted(n1agent)
	select {
	case nodeEvent := <-dp.NodeAddEvent:
		t.Errorf("Unexpected NodeAdd() event %#v", nodeEvent)
	case nodeEvent := <-dp.NodeUpdateEvent:
		t.Errorf("Unexpected NodeUpdate() event %#v", nodeEvent)
	case nodeEvent := <-dp.NodeDeleteEvent:
		require.Equal(t, n1agent, nodeEvent)
	case <-time.After(3 * time.Second):
		t.Errorf("timeout while waiting for NodeDelete() event for node1")
	}
}

func BenchmarkUpdateAndDeleteCycle(b *testing.B) {
	dp := fakenode.NewHandler()
	h, _ := cell.NewSimpleHealth()
	logger := hivetest.Logger(b)
	mngr, err := New(logger, NewNodeMetrics(), h, nil, nil, nil, nil)
	require.NoError(b, err)
	mngr.Subscribe(dp)
	defer mngr.Stop(context.TODO())

	for i := 0; b.Loop(); i++ {
		n := nodeTypes.Node{Name: fmt.Sprintf("%d", i), Source: source.Local}
		mngr.NodeUpdated(n)
	}

	for i := 0; b.Loop(); i++ {
		n := nodeTypes.Node{Name: fmt.Sprintf("%d", i), Source: source.Local}
		mngr.NodeDeleted(n)
	}
	b.StopTimer()
}

func TestClusterSizeDependantInterval(t *testing.T) {
	logger := hivetest.Logger(t)

	dp := fakenode.NewHandler()
	h, _ := cell.NewSimpleHealth()
	mngr, err := New(logger, NewNodeMetrics(), h, nil, nil, nil, nil)
	require.NoError(t, err)
	mngr.Subscribe(dp)
	defer mngr.Stop(context.TODO())

	prevInterval := time.Nanosecond

	for i := range 1000 {
		n := nodeTypes.Node{Name: fmt.Sprintf("%d", i), Source: source.Local, IPAddresses: []nodeTypes.Address{
			{
				Type: addressing.NodeInternalIP,
				IP:   net.ParseIP("10.0.0.1"),
			},
		}}
		mngr.NodeUpdated(n)
		newInterval := mngr.ClusterSizeDependantInterval(time.Minute)
		assert.Greater(t, newInterval, prevInterval)
	}
}

func TestBackgroundSync(t *testing.T) {
	signalNodeHandler := newSignalNodeHandler()
	signalNodeHandler.EnableNodeValidateImplementationEvent = true
	h, _ := cell.NewSimpleHealth()
	logger := hivetest.Logger(t)
	mngr, err := New(logger, NewNodeMetrics(), h, nil, nil, nil, nil)
	mngr.Subscribe(signalNodeHandler)
	require.NoError(t, err)
	defer mngr.Stop(context.TODO())

	numNodes := 128

	allNodeValidateCallsReceived := &sync.WaitGroup{}
	allNodeValidateCallsReceived.Add(1)

	go func() {
		nodeValidationsReceived := 0
		for {
			select {
			case <-signalNodeHandler.NodeValidateImplementationEvent:
				nodeValidationsReceived++
				if nodeValidationsReceived >= numNodes {
					allNodeValidateCallsReceived.Done()
					return
				}
			case <-time.After(1 * time.Second):
				t.Errorf("Timeout while waiting for NodeValidateImplementation() to be called")
				allNodeValidateCallsReceived.Done()
				return
			}
		}
	}()

	for i := range numNodes {
		n := nodeTypes.Node{Name: fmt.Sprintf("%d", i), Source: source.Kubernetes, IPAddresses: []nodeTypes.Address{
			{
				Type: addressing.NodeInternalIP,
				IP:   net.ParseIP("10.0.0.1"),
			},
		}}
		mngr.NodeUpdated(n)
	}

	mngr.singleBackgroundLoop(context.Background(), time.Millisecond)

	allNodeValidateCallsReceived.Wait()
}

func TestNode(t *testing.T) {
	dp := newSignalNodeHandler()
	dp.EnableNodeAddEvent = true
	dp.EnableNodeUpdateEvent = true
	dp.EnableNodeDeleteEvent = true
	h, _ := cell.NewSimpleHealth()
	logger := hivetest.Logger(t)
	mngr, err := New(logger, NewNodeMetrics(), h, nil, nil, nil, nil)
	require.NoError(t, err)
	mngr.Subscribe(dp)
	defer mngr.Stop(context.TODO())

	n1 := nodeTypes.Node{
		Name:    "node1",
		Cluster: "c1",
		IPAddresses: []nodeTypes.Address{
			{
				Type: addressing.NodeCiliumInternalIP,
				IP:   net.ParseIP("192.0.2.1"),
			},
			{
				Type: addressing.NodeCiliumInternalIP,
				IP:   net.ParseIP("2001:DB8::1"),
			},
		},
		IPv4HealthIP: iputil.AddrFrom(netip.MustParseAddr("192.0.2.2")),
		IPv6HealthIP: iputil.AddrFrom(netip.MustParseAddr("2001:DB8::2")),
		Source:       source.KVStore,
	}
	mngr.NodeUpdated(n1)

	select {
	case nodeEvent := <-dp.NodeAddEvent:
		require.Equal(t, n1, nodeEvent)
	case nodeEvent := <-dp.NodeUpdateEvent:
		t.Errorf("Unexpected NodeUpdate() event %#v", nodeEvent)
	case nodeEvent := <-dp.NodeDeleteEvent:
		t.Errorf("Unexpected NodeDelete() event %#v", nodeEvent)
	case <-time.After(3 * time.Second):
		t.Errorf("timeout while waiting for NodeAdd() event for node1")
	}

	n1V2 := n1.DeepCopy()
	n1V2.IPAddresses = []nodeTypes.Address{
		{
			Type: addressing.NodeCiliumInternalIP,
			IP:   net.ParseIP("192.0.2.10"),
		},
		{
			// We will keep the IPv6 the same to make sure we will not delete it
			Type: addressing.NodeCiliumInternalIP,
			IP:   net.ParseIP("2001:DB8::1"),
		},
	}
	n1V2.IPv4HealthIP = iputil.AddrFrom(netip.MustParseAddr("192.0.2.20"))
	n1V2.IPv6HealthIP = iputil.AddrFrom(netip.MustParseAddr("2001:DB8::20"))
	mngr.NodeUpdated(*n1V2)

	select {
	case nodeEvent := <-dp.NodeAddEvent:
		t.Errorf("Unexpected NodeAdd() event %#v", nodeEvent)
	case nodeEvent := <-dp.NodeUpdateEvent:
		require.Equal(t, *n1V2, nodeEvent)
	case nodeEvent := <-dp.NodeDeleteEvent:
		t.Errorf("Unexpected NodeDelete() event %#v", nodeEvent)
	case <-time.After(3 * time.Second):
		t.Errorf("timeout while waiting for NodeUpdate() event for node2")
	}

	nodes := mngr.GetNodes()
	require.Len(t, nodes, 1)
	n, ok := nodes[n1.Identity()]
	require.True(t, ok)
	// Needs to be the same as n2
	require.Equal(t, *n1V2, n)
}

func TestNodeManagerEmitStatus(t *testing.T) {
	// Tests health reporting on node manager.
	assert := assert.New(t)

	var (
		statusTable statedb.Table[types.Status]
		db          *statedb.DB
		nh1         *signalNodeHandler
	)

	baseBackgroundSyncInterval = 1 * time.Millisecond
	fn := func(m *manager, sh hive.Shutdowner, st statedb.Table[types.Status], d *statedb.DB, lifecycle cell.Lifecycle) {
		m.nodes[nodeTypes.Identity{
			Name:    "node1",
			Cluster: "c1",
		}] = &nodeEntry{node: nodeTypes.Node{Name: "node1", Cluster: "c1"}}
		m.nodeHandlers = make(map[node.Handler]struct{})
		nh1 = newSignalNodeHandler()
		nh1.EnableNodeValidateImplementationEvent = true
		// By default this is a buffered channel, by making it a non-buffered
		// channel we can sync up iterations of background sync.
		nh1.NodeValidateImplementationEvent = make(chan nodeTypes.Node)
		m.nodeHandlers[nh1] = struct{}{}

		statusTable = st
		db = d

		lifecycle.Append(m)
	}

	hive := hive.New(
		cell.Provide(func() testParams {
			return testParams{NodeMetrics: NewNodeMetrics()}
		}),
		cell.Provide(tables.NewDeviceTable),
		cell.Provide(statedb.RWTable[*tables.Device].ToTable),
		cell.Provide(node.NewNodeTable),
		cell.Module("node_manager", "Node Manager", cell.Provide(New)),
		cell.Invoke(fn),
	)
	l := hivetest.Logger(t, hivetest.LogLevel(slog.LevelDebug))
	hive.Populate(l)

	checkStatus := func() (types.Status, <-chan struct{}) {
		id := types.Identifier{
			Module:    cell.FullModuleID{"node_manager"},
			Component: []string{"job-backgroundSync"},
		}

		rx := db.ReadTxn()
		ss, _, watch, found := statusTable.GetWatch(rx, health.PrimaryIndex.Query(id.HealthID()))
		if !found {
			_, watch = statusTable.AllWatch(rx)
		}

		return ss, watch
	}

	err := hive.Start(l, context.Background())
	assert.NoError(err)
	defer hive.Stop(l, context.Background())

	// Initially the status does not exist. When the job starts to run, the
	// status will be "OK". Wait for the status to be "OK".
	var (
		status types.Status
		watch  <-chan struct{}
	)
	for {
		status, watch = checkStatus()
		if status.Level == "" {
			<-watch
			continue
		}

		assert.Equal(types.LevelOK, string(status.Level))
		break
	}

	// Unblock background sync by reading event. After this we expect the
	// status to switch to "Degraded", due to the test error set below
	nh1.NodeValidateImplementationEventError = fmt.Errorf("test error")
	<-nh1.NodeValidateImplementationEvent
	<-watch
	status, watch = checkStatus()
	assert.Equal(types.LevelDegraded, string(status.Level))

	// Stop returning an error and unblock background sync by reading event. After
	// this we expect the status to switch to "OK"
	nh1.NodeValidateImplementationEventError = nil
	<-nh1.NodeValidateImplementationEvent
	<-watch
	status, _ = checkStatus()
	assert.Equal(types.LevelOK, string(status.Level))

	for range cap(nh1.Stop) {
		nh1.Stop <- struct{}{}
	}
}

var _ cell.Health = (*mockHealth)(nil)

type mockHealth struct {
	ok chan struct{}
}

func (mh *mockHealth) OK(status string) {
	mh.ok <- struct{}{}
}

func (mh *mockHealth) Degraded(reason string, err error) {
}

func (mh *mockHealth) Stopped(reason string) {
}

func (mh *mockHealth) NewScope(name string) cell.Health {
	return mh
}

func (mh *mockHealth) Close() {}

type testParams struct {
	cell.Out
	NodeMetrics *nodeMetrics
}

func TestNodeWithSameInternalIP(t *testing.T) {
	logger := hivetest.Logger(t)
	dp := newSignalNodeHandler()
	dp.EnableNodeAddEvent = true
	dp.EnableNodeUpdateEvent = true
	dp.EnableNodeDeleteEvent = true
	h, _ := cell.NewSimpleHealth()
	mngr, err := New(logger, NewNodeMetrics(), h, nil, nil, nil, nil)
	require.NoError(t, err)
	mngr.Subscribe(dp)
	defer mngr.Stop(context.TODO())

	n1 := nodeTypes.Node{
		Name:    "node1",
		Cluster: "c1",
		IPAddresses: []nodeTypes.Address{
			{
				Type: addressing.NodeInternalIP,
				IP:   net.ParseIP("10.128.0.40"),
			},
			{
				Type: addressing.NodeExternalIP,
				IP:   net.ParseIP("34.171.135.203"),
			},
			{
				Type: addressing.NodeCiliumInternalIP,
				IP:   net.ParseIP("169.254.4.6"),
			},
		},
		Source: source.Local,
	}
	mngr.NodeUpdated(n1)

	select {
	case nodeEvent := <-dp.NodeAddEvent:
		require.Equal(t, n1, nodeEvent)
	case nodeEvent := <-dp.NodeUpdateEvent:
		t.Errorf("Unexpected NodeUpdate() event %#v", nodeEvent)
	case nodeEvent := <-dp.NodeDeleteEvent:
		t.Errorf("Unexpected NodeDelete() event %#v", nodeEvent)
	case <-time.After(3 * time.Second):
		t.Errorf("timeout while waiting for NodeAdd() event for node1")
	}

	n2 := nodeTypes.Node{
		Name:    "node2",
		Cluster: "c1",
		IPAddresses: []nodeTypes.Address{
			{
				Type: addressing.NodeInternalIP,
				IP:   net.ParseIP("10.128.0.110"),
			},
			{
				Type: addressing.NodeExternalIP,
				IP:   net.ParseIP("34.170.71.139"),
			},
			{
				Type: addressing.NodeCiliumInternalIP,
				IP:   net.ParseIP("169.254.4.6"),
			},
		},
		Source: source.CustomResource,
	}
	mngr.NodeUpdated(n2)

	select {
	case nodeEvent := <-dp.NodeAddEvent:
		require.Equal(t, n2, nodeEvent)
	case nodeEvent := <-dp.NodeUpdateEvent:
		t.Errorf("Unexpected NodeUpdate() event %#v", nodeEvent)
	case nodeEvent := <-dp.NodeDeleteEvent:
		t.Errorf("Unexpected NodeDelete() event %#v", nodeEvent)
	case <-time.After(3 * time.Second):
		t.Errorf("timeout while waiting for NodeAdd() event for node1")
	}
}

func TestNodeTableMirroring(t *testing.T) {
	logger := hivetest.Logger(t)
	db := statedb.New()
	nodeTable, err := node.NewNodeTable(db)
	require.NoError(t, err)

	h, _ := cell.NewSimpleHealth()
	mngr, err := New(logger, NewNodeMetrics(), h, nil, db, nil, nodeTable)
	require.NoError(t, err)

	initialized, initWatch := nodeTable.Initialized(db.ReadTxn())
	require.False(t, initialized)
	require.ElementsMatch(t, []string{
		ClusterNodeTableInitializerName,
		MeshNodeTableInitializerName,
	}, nodeTable.PendingInitializers(db.ReadTxn()))

	n1 := nodeTypes.Node{
		Name:    "node1",
		Cluster: "c1",
		IPAddresses: []nodeTypes.Address{{
			Type: addressing.NodeInternalIP,
			IP:   net.ParseIP("10.0.0.1"),
		}},
		Source: source.KVStore,
	}
	n2 := nodeTypes.Node{
		Name:    "node2",
		Cluster: "c1",
		IPAddresses: []nodeTypes.Address{{
			Type: addressing.NodeInternalIP,
			IP:   net.ParseIP("10.0.0.2"),
		}},
		Source: source.KVStore,
	}

	requireNode := func(t *testing.T, n nodeTypes.Node) {
		stored, _, found := nodeTable.Get(db.ReadTxn(), node.NodeByName(n.Fullname()))
		require.True(t, found)
		require.Equal(t, node.Node{Node: n}, *stored)
	}
	requireNoNode := func(t *testing.T, n nodeTypes.Node) {
		_, _, found := nodeTable.Get(db.ReadTxn(), node.NodeByName(n.Fullname()))
		require.False(t, found)
	}

	mngr.NodeUpdated(n1)
	requireNode(t, n1)

	n1.EncryptionKey = 42
	mngr.NodeUpdated(n1)
	requireNode(t, n1)

	mngr.NodeUpdated(n2)
	requireNode(t, n1)
	requireNode(t, n2)

	select {
	case <-initWatch:
		t.Fatal("node table initialized before NodeSync")
	default:
	}

	initialized, _ = nodeTable.Initialized(db.ReadTxn())
	require.False(t, initialized)

	mngr.NodeSync()
	require.Equal(t, []string{
		MeshNodeTableInitializerName,
	}, nodeTable.PendingInitializers(db.ReadTxn()))

	select {
	case <-initWatch:
		t.Fatal("node table initialized before MeshNodeSync")
	default:
	}

	mngr.MeshNodeSync()

	select {
	case <-initWatch:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for node table initializer")
	}
	initialized, _ = nodeTable.Initialized(db.ReadTxn())
	require.True(t, initialized)

	mngr.NodeDeleted(n1)
	requireNoNode(t, n1)
	requireNode(t, n2)
}

func TestNodeTableInitializersCompleteInEitherOrder(t *testing.T) {
	for _, meshFirst := range []bool{false, true} {
		name := "cluster-first"
		if meshFirst {
			name = "mesh-first"
		}
		t.Run(name, func(t *testing.T) {
			db := statedb.New()
			nodeTable, err := node.NewNodeTable(db)
			require.NoError(t, err)

			health, _ := cell.NewSimpleHealth()
			mngr, err := New(
				hivetest.Logger(t),
				NewNodeMetrics(),
				health,
				nil,
				db,
				nil,
				nodeTable,
			)
			require.NoError(t, err)

			if meshFirst {
				mngr.MeshNodeSync()
				require.Equal(t, []string{
					ClusterNodeTableInitializerName,
				}, nodeTable.PendingInitializers(db.ReadTxn()))
				mngr.NodeSync()
			} else {
				mngr.NodeSync()
				require.Equal(t, []string{
					MeshNodeTableInitializerName,
				}, nodeTable.PendingInitializers(db.ReadTxn()))
				mngr.MeshNodeSync()
			}

			initialized, _ := nodeTable.Initialized(db.ReadTxn())
			require.True(t, initialized)
		})
	}
}
