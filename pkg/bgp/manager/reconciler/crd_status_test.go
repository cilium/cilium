// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package reconciler

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/hivetest"
	"github.com/cilium/hive/job"
	"github.com/cilium/statedb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/watch"
	k8sTesting "k8s.io/client-go/testing"
	"k8s.io/utils/ptr"

	"github.com/cilium/cilium/api/v1/models"
	daemon_k8s "github.com/cilium/cilium/daemon/k8s"
	"github.com/cilium/cilium/pkg/bgp/manager/instance"
	"github.com/cilium/cilium/pkg/bgp/manager/store"
	"github.com/cilium/cilium/pkg/bgp/manager/tables"
	"github.com/cilium/cilium/pkg/bgp/types"
	"github.com/cilium/cilium/pkg/hive"
	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client"
	cilium_client_v2 "github.com/cilium/cilium/pkg/k8s/client/clientset/versioned/typed/cilium.io/v2"
	k8sFakeClient "github.com/cilium/cilium/pkg/k8s/client/testutils"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
	"github.com/cilium/cilium/pkg/option"
)

const (
	TestTimeout = time.Second * 5
)

type crdStatusFixture struct {
	hive            *hive.Hive
	reconciler      *StatusReconciler
	db              *statedb.DB
	reconcileErrTbl statedb.RWTable[*tables.BGPReconcileError]
	fakeClientSet   *k8sFakeClient.FakeClientset
	bgpnClient      cilium_client_v2.CiliumBGPNodeConfigInterface
	bgpncMockStore  *store.MockBGPCPResourceStore[*v2.CiliumBGPNodeConfig]
}

func newCRDStatusFixture(ctx context.Context, req *require.Assertions, l *slog.Logger) (*crdStatusFixture, func()) {
	rws := map[string]*struct {
		once    sync.Once
		watchCh chan any
	}{
		"ciliumnodes": {watchCh: make(chan any)},
	}

	f := &crdStatusFixture{}
	f.fakeClientSet, _ = k8sFakeClient.NewFakeClientset(l)
	f.bgpnClient = f.fakeClientSet.CiliumFakeClientset.CiliumV2().CiliumBGPNodeConfigs()

	watchReactorFn := func(action k8sTesting.Action) (handled bool, ret watch.Interface, err error) {
		w := action.(k8sTesting.WatchAction)
		gvr := w.GetResource()
		ns := w.GetNamespace()

		// Extract ListOptions for WatchList semantics (SendInitialEvents)
		var opts []metav1.ListOptions
		if watchAction, ok := action.(k8sTesting.WatchActionImpl); ok {
			opts = append(opts, watchAction.ListOptions)
		}

		watch, err := f.fakeClientSet.CiliumFakeClientset.Tracker().Watch(gvr, ns, opts...)
		if err != nil {
			return false, nil, err
		}
		rw, ok := rws[w.GetResource().Resource]
		if !ok {
			return false, watch, nil
		}
		rw.once.Do(func() { close(rw.watchCh) })
		return true, watch, nil
	}
	f.fakeClientSet.CiliumFakeClientset.PrependWatchReactor("*", watchReactorFn)

	// make sure watchers are initialized before the test starts
	watchersReadyFn := func() {
		for name, rw := range rws {
			select {
			case <-ctx.Done():
				req.Fail(fmt.Sprintf("Context expired while waiting for %s", name))
			case <-rw.watchCh:
			}
		}
	}

	f.hive = hive.New(
		daemon_k8s.ResourcesCell,
		cell.Provide(
			func() *option.DaemonConfig {
				return &option.DaemonConfig{
					EnableBGPControlPlane:             true,
					EnableBGPControlPlaneStatusReport: true,
				}
			},
			tables.NewBGPReconcileErrorTable,
			statedb.RWTable[*tables.BGPReconcileError].ToTable,
		),
		cell.Provide(func() k8sClient.Clientset {
			return f.fakeClientSet
		}),
		cell.Provide(func() store.BGPCPResourceStore[*v2.CiliumBGPNodeConfig] {
			f.bgpncMockStore = store.NewMockBGPCPResourceStore[*v2.CiliumBGPNodeConfig]()
			return f.bgpncMockStore
		}),
		cell.Invoke(
			func(p StatusReconcilerIn) {
				out := NewStatusReconciler(p)
				f.reconciler = out.Reconciler.(*StatusReconciler)
				f.reconciler.reconcileInterval = 100 * time.Millisecond
			}),
		cell.Invoke(func(db *statedb.DB, table statedb.RWTable[*tables.BGPReconcileError]) {
			f.db = db
			f.reconcileErrTbl = table
		}),
	)

	return f, watchersReadyFn
}

func TestCRDConditions(t *testing.T) {
	var tests = []struct {
		name               string
		statedbData        []*tables.BGPReconcileError
		initNodeConfig     *v2.CiliumBGPNodeConfig
		expectedNodeConfig *v2.CiliumBGPNodeConfig
	}{
		{
			name: "new error conditions",
			statedbData: []*tables.BGPReconcileError{
				{
					Instance: "bgp-instance-0",
					ErrorID:  0,
					Error:    "error 00",
				},
				{
					Instance: "bgp-instance-0",
					ErrorID:  1,
					Error:    "error 01",
				},
				{
					Instance: "bgp-instance-1",
					ErrorID:  0,
					Error:    "error 10",
				},
			},
			initNodeConfig: &v2.CiliumBGPNodeConfig{
				ObjectMeta: metav1.ObjectMeta{
					Name:       "node0",
					Generation: 19,
				},
			},
			expectedNodeConfig: &v2.CiliumBGPNodeConfig{
				ObjectMeta: metav1.ObjectMeta{
					Name:       "node0",
					Generation: 19,
				},
				Spec: v2.CiliumBGPNodeSpec{},
				Status: v2.CiliumBGPNodeStatus{
					Conditions: []metav1.Condition{
						{
							Type:               v2.BGPInstanceConditionReconcileError,
							Status:             metav1.ConditionTrue,
							Reason:             "ReconcileFailed",
							ObservedGeneration: 19,
							Message: "bgp-instance-0: error 00\n" +
								"bgp-instance-0: error 01\n" +
								"bgp-instance-1: error 10\n",
						},
					},
				},
			},
		},
		{
			name: "modify previous error conditions",
			statedbData: []*tables.BGPReconcileError{
				{
					Instance: "bgp-instance-0",
					ErrorID:  0,
					Error:    "error 00",
				},
			},
			initNodeConfig: &v2.CiliumBGPNodeConfig{
				ObjectMeta: metav1.ObjectMeta{
					Name: "node0",
				},
				Spec: v2.CiliumBGPNodeSpec{},
				Status: v2.CiliumBGPNodeStatus{
					Conditions: []metav1.Condition{
						{
							Type:   v2.BGPInstanceConditionReconcileError,
							Status: metav1.ConditionTrue,
							Reason: "ReconcileFailed",
							Message: "bgp-instance-0: error 00\n" +
								"bgp-instance-0: error 01\n" +
								"bgp-instance-1: error 10\n",
						},
					},
				},
			},
			expectedNodeConfig: &v2.CiliumBGPNodeConfig{
				ObjectMeta: metav1.ObjectMeta{
					Name: "node0",
				},
				Status: v2.CiliumBGPNodeStatus{
					Conditions: []metav1.Condition{
						{
							Type:    v2.BGPInstanceConditionReconcileError,
							Status:  metav1.ConditionTrue,
							Reason:  "ReconcileFailed",
							Message: "bgp-instance-0: error 00\n",
						},
					},
				},
			},
		},
		{
			name:        "delete previous error conditions",
			statedbData: []*tables.BGPReconcileError{},
			initNodeConfig: &v2.CiliumBGPNodeConfig{
				ObjectMeta: metav1.ObjectMeta{
					Name: "node0",
				},
				Spec: v2.CiliumBGPNodeSpec{},
				Status: v2.CiliumBGPNodeStatus{
					Conditions: []metav1.Condition{
						{
							Type:   v2.BGPInstanceConditionReconcileError,
							Status: metav1.ConditionTrue,
							Reason: "ReconcileFailed",
							Message: "bgp-instance-0: error 00\n" +
								"bgp-instance-0: error 01\n" +
								"bgp-instance-1: error 10\n",
						},
					},
				},
			},
			expectedNodeConfig: &v2.CiliumBGPNodeConfig{
				ObjectMeta: metav1.ObjectMeta{
					Name: "node0",
				},
				Status: v2.CiliumBGPNodeStatus{
					Conditions: []metav1.Condition{
						{
							Type:    v2.BGPInstanceConditionReconcileError,
							Status:  metav1.ConditionFalse,
							Reason:  "ReconcileSucceeded",
							Message: "",
						},
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Set node name before creating fixture so field selectors match
			nodeTypes.SetName("node0")

			ctx, cancel := context.WithTimeout(context.Background(), TestTimeout)
			logger := hivetest.Logger(t, hivetest.LogLevel(slog.LevelDebug))

			f, watcherReadyFn := newCRDStatusFixture(ctx, require.New(t), logger)

			require.NoError(t, f.hive.Start(logger, ctx))
			t.Cleanup(func() {
				f.hive.Stop(logger, ctx)
				cancel()
			})

			// wait for watchers to be ready
			watcherReadyFn()

			// initialize BGP node config
			if tt.initNodeConfig != nil {
				_, err := f.bgpnClient.Create(ctx, tt.initNodeConfig, metav1.CreateOptions{})
				require.NoError(t, err)

				// insert the node config into the mock store
				f.bgpncMockStore.Upsert(tt.initNodeConfig)
			}

			// create local node
			_, err := f.fakeClientSet.CiliumV2().CiliumNodes().Create(
				ctx,
				&v2.CiliumNode{
					ObjectMeta: metav1.ObjectMeta{
						Name: "node0",
					},
				},
				metav1.CreateOptions{},
			)
			require.NoError(t, err)

			// wait for node to be detected by reconciler
			require.EventuallyWithT(t, func(c *assert.CollectT) {
				f.reconciler.Lock()
				defer f.reconciler.Unlock()
				assert.Equal(c, "node0", f.reconciler.nodeName)
			}, time.Second*10, time.Millisecond*100)

			// setup statedb
			txn := f.db.WriteTxn(f.reconcileErrTbl)
			for _, errObj := range tt.statedbData {
				_, _, err := f.reconcileErrTbl.Insert(txn, errObj)
				require.NoError(t, err)
			}
			txn.Commit()

			err = f.reconciler.updateErrorConditions()
			require.NoError(t, err)

			// check eventually the conditions are updated
			require.EventuallyWithT(t, func(c *assert.CollectT) {
				nodeConfig, err := f.bgpnClient.Get(ctx, "node0", metav1.GetOptions{})
				if !assert.NoError(c, err) {
					return
				}
				if !assert.Len(c, nodeConfig.Status.Conditions, len(tt.expectedNodeConfig.Status.Conditions)) {
					return
				}

				// we can not compare the whole status object because the timestamp is different.
				for i, cond := range nodeConfig.Status.Conditions {
					assert.Equal(c, tt.expectedNodeConfig.Status.Conditions[i].Type, cond.Type)
					assert.Equal(c, tt.expectedNodeConfig.Status.Conditions[i].ObservedGeneration, cond.ObservedGeneration)
					assert.Equal(c, tt.expectedNodeConfig.Status.Conditions[i].Status, cond.Status)
					assert.Equal(c, tt.expectedNodeConfig.Status.Conditions[i].Reason, cond.Reason)
					assert.Equal(c, tt.expectedNodeConfig.Status.Conditions[i].Message, cond.Message)
				}
			}, time.Second*10, time.Millisecond*100)
		})
	}
}

func TestDisableStatusReport(t *testing.T) {
	ctx := context.TODO()
	logger := hivetest.Logger(t)
	nodeTypes.SetName("node0")

	var cs k8sClient.Clientset
	hive := hive.New(
		daemon_k8s.ResourcesCell,
		cell.Provide(
			func() *option.DaemonConfig {
				return &option.DaemonConfig{
					EnableBGPControlPlane:             true,
					EnableBGPControlPlaneStatusReport: false,
				}
			},
			k8sFakeClient.NewFakeClientset,
		),
		cell.Invoke(func(jg job.Group, ln daemon_k8s.LocalCiliumNodeResource, _cs k8sClient.Clientset) {
			cs = _cs

			// Create a LocalNode to obtain local node name
			_, err := cs.CiliumV2().CiliumNodes().Create(
				ctx,
				&v2.CiliumNode{
					ObjectMeta: metav1.ObjectMeta{
						Name: "node0",
					},
				},
				metav1.CreateOptions{},
			)
			require.NoError(t, err)

			// Create a NodeConfig for this node
			_, err = cs.CiliumV2().CiliumBGPNodeConfigs().Create(
				ctx,
				&v2.CiliumBGPNodeConfig{
					ObjectMeta: metav1.ObjectMeta{
						Name: "node0",
					},
					// Spec can be empty for this test
					Spec: v2.CiliumBGPNodeSpec{},
					// Fill with some dummy status
					Status: v2.CiliumBGPNodeStatus{
						BGPInstances: []v2.CiliumBGPNodeInstanceStatus{
							{
								Name: "foo",
							},
						},
					},
				},

				metav1.CreateOptions{},
			)
			require.NoError(t, err)

			// Ensure the status is not empty at this point
			nc, err := cs.CiliumV2().CiliumBGPNodeConfigs().Get(ctx, "node0", metav1.GetOptions{})
			require.NoError(t, err)
			require.False(t, nc.Status.DeepEqual(&v2.CiliumBGPNodeStatus{}), "Status is already empty before cleanup job")

			// Register cleanup job. This should cleanup the status of the NodeConfig above.
			r := &StatusReconciler{
				LocalNodeResource: ln,
				ClientSet:         cs,
			}
			jg.Add(job.OneShot("cleanup-status", r.cleanupStatus))
		}),
	)

	require.NoError(t, hive.Start(logger, ctx))
	t.Cleanup(func() {
		hive.Stop(logger, ctx)
	})

	// Wait for status to be cleared
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		nc, err := cs.CiliumV2().CiliumBGPNodeConfigs().Get(ctx, "node0", metav1.GetOptions{})
		if !assert.NoError(ct, err) {
			return
		}
		// The status should be cleared to empty
		assert.True(ct, nc.Status.DeepEqual(&v2.CiliumBGPNodeStatus{}), "Status is not empty")
	}, time.Second*5, time.Millisecond*100)
}

// TestSamePeer covers matching a peer from the running gobgp state against its CRD
// configuration, which decides whether that peer gets any state reported at all.
func TestSamePeer(t *testing.T) {
	tests := []struct {
		name       string
		running    *models.BgpPeer
		configured v2.CiliumBGPNodePeer
		want       bool
	}{
		{
			// An unnumbered peer has no PeerAddress in the CRD, so the name is the
			// only key available. Matching on address alone dropped it from the
			// status entirely.
			name:       "unnumbered peer matches on name, resolved link-local address",
			running:    &models.BgpPeer{Name: "dpu-unnumbered", PeerAddress: "fe80::43:57ff:fec5:c00d%enp193s0np0"},
			configured: v2.CiliumBGPNodePeer{Name: "dpu-unnumbered"},
			want:       true,
		},
		{
			name:       "unnumbered peer matches on name before gobgp resolves an address",
			running:    &models.BgpPeer{Name: "dpu-unnumbered", PeerAddress: "enp193s0np0"},
			configured: v2.CiliumBGPNodePeer{Name: "dpu-unnumbered"},
			want:       true,
		},
		{
			// The running state reports the canonical form from netip.Addr.String(),
			// so a non-canonical CRD spelling never string-matched and the peer was
			// reported with no peering state.
			name:       "non-canonical configured address still matches by name",
			running:    &models.BgpPeer{Name: "dpu-ipv6", PeerAddress: "fc00::"},
			configured: v2.CiliumBGPNodePeer{Name: "dpu-ipv6", PeerAddress: ptr.To("fc00::0")},
			want:       true,
		},
		{
			name:       "different names do not match even when addresses agree",
			running:    &models.BgpPeer{Name: "dpu", PeerAddress: "169.254.100.0"},
			configured: v2.CiliumBGPNodePeer{Name: "dpu-other", PeerAddress: ptr.To("169.254.100.0")},
			want:       false,
		},
		{
			name:       "canonical addresses match by name",
			running:    &models.BgpPeer{Name: "dpu", PeerAddress: "169.254.100.0"},
			configured: v2.CiliumBGPNodePeer{Name: "dpu", PeerAddress: ptr.To("169.254.100.0")},
			want:       true,
		},
		{
			// Peers predating the Description encoding carry no name; fall back to
			// comparing parsed addresses so non-canonical spellings still match.
			name:       "unnamed running peer falls back to parsed address, non-canonical",
			running:    &models.BgpPeer{PeerAddress: "fc00::"},
			configured: v2.CiliumBGPNodePeer{PeerAddress: ptr.To("fc00::0")},
			want:       true,
		},
		{
			name:       "unnamed running peer falls back to parsed address, mismatch",
			running:    &models.BgpPeer{PeerAddress: "fc00::1"},
			configured: v2.CiliumBGPNodePeer{PeerAddress: ptr.To("fc00::2")},
			want:       false,
		},
		{
			name:       "unnamed running peer with no configured address does not match",
			running:    &models.BgpPeer{PeerAddress: "fc00::"},
			configured: v2.CiliumBGPNodePeer{},
			want:       false,
		},
		{
			// An unresolved unnumbered peer reports its interface name, which is not
			// an address; it must not be mistaken for one.
			name:       "unnamed running peer with unparseable address does not match",
			running:    &models.BgpPeer{PeerAddress: "enp193s0np0"},
			configured: v2.CiliumBGPNodePeer{PeerAddress: ptr.To("fc00::")},
			want:       false,
		},
		{
			name:       "named configured peer does not match an unnamed running peer",
			running:    &models.BgpPeer{PeerAddress: "169.254.100.0"},
			configured: v2.CiliumBGPNodePeer{Name: "dpu", PeerAddress: ptr.To("169.254.100.0")},
			want:       false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.want, samePeer(tt.running, tt.configured))
		})
	}
}

// stubPeerStateRouter serves a canned legacy peer state, standing in for what gobgp
// reports. It embeds the fake router so only GetPeerStateLegacy is overridden, leaving
// the shared fake's behaviour untouched for every other test.
type stubPeerStateRouter struct {
	types.Router
	peers []*models.BgpPeer
}

func (s *stubPeerStateRouter) GetPeerStateLegacy(context.Context) (types.GetPeerStateLegacyResponse, error) {
	return types.GetPeerStateLegacyResponse{Peers: s.peers}, nil
}

// TestGetInstanceStatusPeers checks which configured peers make it into the reported
// CiliumBGPNodeConfig status, and what address each is reported with.
func TestGetInstanceStatusPeers(t *testing.T) {
	req := require.New(t)

	inst := instance.NewFakeBGPInstance()
	inst.Config = &v2.CiliumBGPNodeInstance{
		Name:     "bgp-k8s",
		LocalASN: ptr.To[int64](4294841000),
		Peers: []v2.CiliumBGPNodePeer{
			// Unnumbered: no PeerAddress in the CRD at all.
			{Name: "dpu-unnumbered", PeerASN: ptr.To[int64](4290246000)},
			// Non-canonical spelling of the address gobgp reports as "fc00::".
			{Name: "dpu-ipv6", PeerASN: ptr.To[int64](4290246000), PeerAddress: ptr.To("fc00::0")},
			{Name: "dpu", PeerASN: ptr.To[int64](4290246000), PeerAddress: ptr.To("169.254.100.0")},
			// Configured but not present in the running state.
			{Name: "dpu-absent", PeerASN: ptr.To[int64](4290246000), PeerAddress: ptr.To("169.254.100.2")},
		},
	}
	inst.Router = &stubPeerStateRouter{
		Router: inst.Router,
		peers: []*models.BgpPeer{
			{Name: "dpu-unnumbered", PeerAddress: "fe80::43:57ff:fec5:c00d%enp193s0np0", SessionState: "established"},
			{Name: "dpu-ipv6", PeerAddress: "fc00::", SessionState: "established"},
			{Name: "dpu", PeerAddress: "169.254.100.0", SessionState: "idle"},
		},
	}

	r := &StatusReconciler{Logger: hivetest.Logger(t)}
	status, err := r.getInstanceStatus(context.Background(), inst)
	req.NoError(err)

	got := map[string]v2.CiliumBGPNodePeerStatus{}
	for _, p := range status.PeerStatuses {
		got[p.Name] = p
	}

	// Every configured peer is reported, including the unnumbered one that carries no
	// CRD address and previously was dropped entirely.
	req.Len(status.PeerStatuses, 4)

	// The unnumbered peer is reported with the address gobgp discovered via ND.
	req.Equal("fe80::43:57ff:fec5:c00d%enp193s0np0", got["dpu-unnumbered"].PeerAddress)
	req.Equal("established", ptr.Deref(got["dpu-unnumbered"].PeeringState, ""))

	// A non-canonical CRD address still matches, and is normalised to the canonical
	// form the router reports.
	req.Equal("fc00::", got["dpu-ipv6"].PeerAddress)
	req.Equal("established", ptr.Deref(got["dpu-ipv6"].PeeringState, ""))

	req.Equal("169.254.100.0", got["dpu"].PeerAddress)
	req.Equal("idle", ptr.Deref(got["dpu"].PeeringState, ""))

	// A peer with no running counterpart keeps its configured address and reports no
	// session state.
	req.Equal("169.254.100.2", got["dpu-absent"].PeerAddress)
	req.Nil(got["dpu-absent"].PeeringState)
}
