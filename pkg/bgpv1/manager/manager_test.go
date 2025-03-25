// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package manager

import (
	"context"
	"fmt"
	"net/netip"
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/cilium/statedb"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"

	restapi "github.com/cilium/cilium/api/v1/server/restapi/bgp"
	"github.com/cilium/cilium/pkg/bgpv1/agent/mode"
	"github.com/cilium/cilium/pkg/bgpv1/manager/instance"
	"github.com/cilium/cilium/pkg/bgpv1/manager/reconcilerv2"
	"github.com/cilium/cilium/pkg/bgpv1/manager/tables"
	"github.com/cilium/cilium/pkg/bgpv1/types"
	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
)

var (
	testSingleIPv4Prefix = []netip.Prefix{
		netip.MustParsePrefix("192.168.0.0/24"),
	}
	testSingleIPv6Prefix = []netip.Prefix{
		netip.MustParsePrefix("2001:DB8::/32"),
	}

	testRouterASN         = 64125
	testInvalidRouterASN  = 4126
	testNeighborIP        = "5.6.7.8"
	testInvalidNeighborIP = "1.2.3.4"

	tableTypeLocRib       = "loc-rib"
	tableTypeLocAdjRibOut = "adj-rib-out"
	afiIPv4               = "ipv4"
	afiIPv6               = "ipv6"
	safiUnicast           = "unicast"
)

// TestGetRoutes tests GetRoutes API of the Manager.
func TestGetRoutes(t *testing.T) {

	var table = []struct {
		// name of the test case
		name string

		// advertised prefixes
		advertisedPrefixes []netip.Prefix
		// expected prefixes
		expectedPrefixes []netip.Prefix

		// GetRoutes params
		routerASN *int64
		tableType string
		afi       string
		safi      string
		neighbor  *string

		// non-nil if error is expected, nil if not
		expectedErr error
	}{
		{
			name:               "single IPv4 prefix - retrieve IPv4",
			advertisedPrefixes: testSingleIPv4Prefix,
			expectedPrefixes:   testSingleIPv4Prefix,
			routerASN:          ptr.To[int64](int64(testRouterASN)),
			tableType:          tableTypeLocRib,
			afi:                afiIPv4,
			safi:               safiUnicast,
			neighbor:           nil,
			expectedErr:        nil,
		},
		{
			name:               "single IPv4 prefix - retrieve IPv6",
			advertisedPrefixes: testSingleIPv4Prefix,
			expectedPrefixes:   nil,
			routerASN:          ptr.To[int64](int64(testRouterASN)),
			tableType:          tableTypeLocRib,
			afi:                afiIPv6,
			safi:               safiUnicast,
			neighbor:           nil,
			expectedErr:        nil,
		},
		{
			name:               "single IPv6 prefix - retrieve IPv6",
			advertisedPrefixes: testSingleIPv6Prefix,
			expectedPrefixes:   testSingleIPv6Prefix,
			routerASN:          nil,
			tableType:          tableTypeLocRib,
			afi:                afiIPv6,
			safi:               safiUnicast,
			neighbor:           nil,
			expectedErr:        nil,
		},
		{
			name:               "mixed IPv4 & IPv6 prefixes - retrieve IPv6",
			advertisedPrefixes: []netip.Prefix{testSingleIPv4Prefix[0], testSingleIPv6Prefix[0]},
			routerASN:          nil,
			expectedPrefixes:   testSingleIPv6Prefix,
			tableType:          tableTypeLocRib,
			afi:                afiIPv6,
			safi:               safiUnicast,
			neighbor:           nil,
			expectedErr:        nil,
		},
		{
			name:               "incorrect ASN",
			advertisedPrefixes: testSingleIPv4Prefix,
			expectedPrefixes:   nil,
			routerASN:          ptr.To[int64](int64(testInvalidRouterASN)),
			tableType:          tableTypeLocRib,
			afi:                afiIPv4,
			safi:               safiUnicast,
			neighbor:           nil,
			expectedErr:        fmt.Errorf(""),
		},
		{
			name:               "unspecified neighbor for adj-rib-out",
			advertisedPrefixes: testSingleIPv4Prefix,
			expectedPrefixes:   nil, // nil as the neighbor never goes UP
			routerASN:          nil,
			tableType:          tableTypeLocAdjRibOut,
			afi:                afiIPv4,
			safi:               safiUnicast,
			neighbor:           nil,
			expectedErr:        nil,
		},
		{
			name:               "valid neighbor",
			advertisedPrefixes: testSingleIPv4Prefix,
			expectedPrefixes:   nil, // nil as the neighbor never goes UP
			routerASN:          nil,
			tableType:          tableTypeLocAdjRibOut,
			afi:                afiIPv4,
			safi:               safiUnicast,
			neighbor:           ptr.To[string](testNeighborIP),
			expectedErr:        nil,
		},
		{
			name:               "non-existing neighbor",
			advertisedPrefixes: testSingleIPv4Prefix,
			expectedPrefixes:   nil,
			routerASN:          nil,
			tableType:          tableTypeLocAdjRibOut,
			afi:                afiIPv4,
			safi:               safiUnicast,
			neighbor:           ptr.To[string](testInvalidNeighborIP),
			expectedErr:        fmt.Errorf(""),
		},
	}

	for _, tt := range table {
		t.Run(tt.name, func(t *testing.T) {
			// set up BGPRouterManager with one BGP server
			srvParams := types.ServerParameters{
				Global: types.BGPGlobal{
					ASN:        uint32(testRouterASN),
					RouterID:   "127.0.0.1",
					ListenPort: -1,
				},
			}
			testSC, err := instance.NewServerWithConfig(context.Background(), hivetest.Logger(t), srvParams)
			require.NoError(t, err)

			testSC.Config = &v2alpha1.CiliumBGPVirtualRouter{
				LocalASN:  int64(testRouterASN),
				Neighbors: []v2alpha1.CiliumBGPNeighbor{},
			}
			cm := mode.NewConfigMode()
			cm.Set(mode.BGPv1)

			brm := &BGPRouterManager{
				ConfigMode: cm,
				Servers: map[int64]*instance.ServerWithConfig{
					int64(testRouterASN): testSC,
				},
				running: true,
			}

			// add a neighbor
			n := &v2alpha1.CiliumBGPNeighbor{
				PeerAddress: testNeighborIP + "/32",
				PeerASN:     64100,
			}
			n.SetDefaults()
			err = testSC.Server.AddNeighbor(context.Background(), types.ToNeighborV1(n, ""))
			require.NoError(t, err)

			// advertise test-provided prefixes
			for _, cidr := range tt.advertisedPrefixes {
				_, err := testSC.Server.AdvertisePath(context.Background(), types.PathRequest{
					Path: types.NewPathForPrefix(cidr),
				})
				require.NoError(t, err)
			}

			// retrieve routes from server's local RIB and
			routes, err := brm.GetRoutes(context.Background(), restapi.GetBgpRoutesParams{
				RouterAsn: tt.routerASN,
				TableType: tt.tableType,
				Afi:       tt.afi,
				Safi:      tt.safi,
				Neighbor:  tt.neighbor,
			})
			if tt.expectedErr == nil {
				require.NoError(t, err)
			} else {
				require.Error(t, err)
			}

			// ensure retrieved routes match expected prefixes
			var retrievedPrefixes []netip.Prefix
			for _, r := range routes {
				retrievedPrefixes = append(retrievedPrefixes, netip.MustParsePrefix(r.Prefix))
			}
			require.Equal(t, tt.expectedPrefixes, retrievedPrefixes)
		})
	}
}

func TestStatedbReconcileErrors(t *testing.T) {
	var tests = []struct {
		name            string
		instances       []*instance.BGPInstance
		reconcilers     []reconcilerv2.ConfigReconciler
		initStatedb     []*tables.BGPReconcileError
		expectedError   bool
		expectedStatedb []*tables.BGPReconcileError
	}{
		{
			name: "No reconciler error",
			instances: []*instance.BGPInstance{
				instance.NewFakeBGPInstanceWithName("instance-1"),
				instance.NewFakeBGPInstanceWithName("instance-2"),
			},
			reconcilers: []reconcilerv2.ConfigReconciler{
				reconcilerv2.NewFakeReconciler(reconcilerv2.FakeReconcilerParams{
					Name: "reconciler-1",
					ReconcilerFunc: func(ctx context.Context, p reconcilerv2.ReconcileParams) error {
						return nil
					},
				}),
				reconcilerv2.NewFakeReconciler(reconcilerv2.FakeReconcilerParams{
					Name: "reconciler-2",
					ReconcilerFunc: func(ctx context.Context, p reconcilerv2.ReconcileParams) error {
						return nil
					},
				}),
			},
			initStatedb:     []*tables.BGPReconcileError{},
			expectedStatedb: []*tables.BGPReconcileError{},
		},
		{
			name: "Both reconcilers return error, for two instances",
			instances: []*instance.BGPInstance{
				instance.NewFakeBGPInstanceWithName("instance-1"),
				instance.NewFakeBGPInstanceWithName("instance-2"),
			},
			reconcilers: []reconcilerv2.ConfigReconciler{
				reconcilerv2.NewFakeReconciler(reconcilerv2.FakeReconcilerParams{
					Name: "reconciler-1",
					ReconcilerFunc: func(ctx context.Context, p reconcilerv2.ReconcileParams) error {
						return fmt.Errorf("reconciler-1 error")
					},
				}),
				reconcilerv2.NewFakeReconciler(reconcilerv2.FakeReconcilerParams{
					Name: "reconciler-2",
					ReconcilerFunc: func(ctx context.Context, p reconcilerv2.ReconcileParams) error {
						return fmt.Errorf("reconciler-2 error")
					},
				}),
			},
			initStatedb:   []*tables.BGPReconcileError{},
			expectedError: true,
			expectedStatedb: []*tables.BGPReconcileError{
				{
					Instance: "instance-1",
					ErrorID:  0,
					Error:    "reconciler-1 error",
				},
				{
					Instance: "instance-1",
					ErrorID:  1,
					Error:    "reconciler-2 error",
				},
				{
					Instance: "instance-2",
					ErrorID:  0,
					Error:    "reconciler-1 error",
				},
				{
					Instance: "instance-2",
					ErrorID:  1,
					Error:    "reconciler-2 error",
				},
			},
		},
		{
			name: "Reconcilers recover from previous error condition",
			instances: []*instance.BGPInstance{
				instance.NewFakeBGPInstanceWithName("instance-1"),
				instance.NewFakeBGPInstanceWithName("instance-2"),
			},
			reconcilers: []reconcilerv2.ConfigReconciler{
				reconcilerv2.NewFakeReconciler(reconcilerv2.FakeReconcilerParams{
					Name: "reconciler-1",
					ReconcilerFunc: func(ctx context.Context, p reconcilerv2.ReconcileParams) error {
						return nil
					},
				}),
				reconcilerv2.NewFakeReconciler(reconcilerv2.FakeReconcilerParams{
					Name: "reconciler-2",
					ReconcilerFunc: func(ctx context.Context, p reconcilerv2.ReconcileParams) error {
						return nil
					},
				}),
			},
			initStatedb: []*tables.BGPReconcileError{
				{
					Instance: "instance-1",
					ErrorID:  0,
					Error:    "reconciler-1 error",
				},
				{
					Instance: "instance-1",
					ErrorID:  1,
					Error:    "reconciler-2 error",
				},
				{
					Instance: "instance-2",
					ErrorID:  0,
					Error:    "reconciler-1 error",
				},
				{
					Instance: "instance-2",
					ErrorID:  1,
					Error:    "reconciler-2 error",
				},
			},
			expectedStatedb: []*tables.BGPReconcileError{},
			expectedError:   false,
		},
		{
			name: "Maximum 5 errors allowed per instance",
			instances: []*instance.BGPInstance{
				instance.NewFakeBGPInstanceWithName("instance-1"),
			},
			reconcilers: []reconcilerv2.ConfigReconciler{
				reconcilerv2.NewFakeReconciler(reconcilerv2.FakeReconcilerParams{
					Name: "reconciler-1",
					ReconcilerFunc: func(ctx context.Context, p reconcilerv2.ReconcileParams) error {
						return fmt.Errorf("reconciler-1 error")
					},
				}),
				reconcilerv2.NewFakeReconciler(reconcilerv2.FakeReconcilerParams{
					Name: "reconciler-2",
					ReconcilerFunc: func(ctx context.Context, p reconcilerv2.ReconcileParams) error {
						return fmt.Errorf("reconciler-2 error")
					},
				}),
				reconcilerv2.NewFakeReconciler(reconcilerv2.FakeReconcilerParams{
					Name: "reconciler-3",
					ReconcilerFunc: func(ctx context.Context, p reconcilerv2.ReconcileParams) error {
						return fmt.Errorf("reconciler-3 error")
					},
				}),
				reconcilerv2.NewFakeReconciler(reconcilerv2.FakeReconcilerParams{
					Name: "reconciler-4",
					ReconcilerFunc: func(ctx context.Context, p reconcilerv2.ReconcileParams) error {
						return fmt.Errorf("reconciler-4 error")
					},
				}),
				reconcilerv2.NewFakeReconciler(reconcilerv2.FakeReconcilerParams{
					Name: "reconciler-5",
					ReconcilerFunc: func(ctx context.Context, p reconcilerv2.ReconcileParams) error {
						return fmt.Errorf("reconciler-5 error")
					},
				}),
				reconcilerv2.NewFakeReconciler(reconcilerv2.FakeReconcilerParams{ // this error is not saved
					Name: "reconciler-6",
					ReconcilerFunc: func(ctx context.Context, p reconcilerv2.ReconcileParams) error {
						return fmt.Errorf("reconciler-6 error")
					},
				}),
			},
			initStatedb: []*tables.BGPReconcileError{},
			expectedStatedb: []*tables.BGPReconcileError{
				{
					Instance: "instance-1",
					ErrorID:  0,
					Error:    "reconciler-1 error",
				},
				{
					Instance: "instance-1",
					ErrorID:  1,
					Error:    "reconciler-2 error",
				},
				{
					Instance: "instance-1",
					ErrorID:  2,
					Error:    "reconciler-3 error",
				},
				{
					Instance: "instance-1",
					ErrorID:  3,
					Error:    "reconciler-4 error",
				},
				{
					Instance: "instance-1",
					ErrorID:  4,
					Error:    "reconciler-5 error",
				},
			},
			expectedError: true,
		},
		{
			name: "abort reconcile error only logged once",
			instances: []*instance.BGPInstance{
				instance.NewFakeBGPInstanceWithName("instance-1"),
			},
			reconcilers: []reconcilerv2.ConfigReconciler{
				reconcilerv2.NewFakeReconciler(reconcilerv2.FakeReconcilerParams{
					Name: "reconciler-1",
					ReconcilerFunc: func(ctx context.Context, p reconcilerv2.ReconcileParams) error {
						return reconcilerv2.ErrAbortReconcile // abort reconcile error
					},
				}),
				reconcilerv2.NewFakeReconciler(reconcilerv2.FakeReconcilerParams{
					Name: "reconciler-2",
					ReconcilerFunc: func(ctx context.Context, p reconcilerv2.ReconcileParams) error {
						return fmt.Errorf("reconciler-2 error")
					},
				}),
				reconcilerv2.NewFakeReconciler(reconcilerv2.FakeReconcilerParams{
					Name: "reconciler-3",
					ReconcilerFunc: func(ctx context.Context, p reconcilerv2.ReconcileParams) error {
						return fmt.Errorf("reconciler-3 error")
					},
				}),
			},
			initStatedb: []*tables.BGPReconcileError{},
			expectedStatedb: []*tables.BGPReconcileError{
				{
					Instance: "instance-1",
					ErrorID:  0,
					Error:    reconcilerv2.ErrAbortReconcile.Error(),
				},
			},
			expectedError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db := statedb.New()
			reconcileErrTbl, err := tables.NewBGPReconcileErrorTable()
			require.NoError(t, err)

			err = db.RegisterTable(reconcileErrTbl)
			require.NoError(t, err)

			testInstances := make(map[string]*instance.BGPInstance)
			for _, inst := range tt.instances {
				testInstances[inst.Name] = inst
			}

			m := BGPRouterManager{
				BGPInstances:        testInstances,
				ConfigReconcilers:   tt.reconcilers,
				DB:                  db,
				ReconcileErrorTable: reconcileErrTbl,
				metrics:             NewBGPManagerMetrics(),
			}

			// init statedb with test data
			txn := db.WriteTxn(m.ReconcileErrorTable)
			for _, errObj := range tt.initStatedb {
				_, _, err = m.ReconcileErrorTable.Insert(txn, errObj)
				require.NoError(t, err)
			}
			txn.Commit()

			// call reconcile for each instance
			for _, inst := range tt.instances {
				err = m.reconcileBGPConfigV2(
					context.Background(),
					inst,
					&v2.CiliumBGPNodeInstance{
						Name: inst.Name,
					},
					&v2.CiliumNode{
						ObjectMeta: metav1.ObjectMeta{
							Name: "node-1",
						},
					},
				)
				if tt.expectedError {
					require.Error(t, err)
				} else {
					require.NoError(t, err)
				}
			}

			// check if the statedb is updated correctly
			var runningStatedb []*tables.BGPReconcileError
			iter := m.ReconcileErrorTable.All(db.ReadTxn())
			for errObj := range iter {
				runningStatedb = append(runningStatedb, errObj)
			}

			require.ElementsMatch(t, tt.expectedStatedb, runningStatedb)
		})
	}
}
