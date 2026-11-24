// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package benchmark

import (
	"iter"
	"net/netip"

	"github.com/cilium/hive/cell"
	"github.com/cilium/statedb"

	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/datapath/tables"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/k8s"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client/testutils"
	"github.com/cilium/cilium/pkg/k8s/resource"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	k8sTables "github.com/cilium/cilium/pkg/k8s/tables"
	"github.com/cilium/cilium/pkg/loadbalancer"
	lbmaps "github.com/cilium/cilium/pkg/loadbalancer/maps"
	lbreconciler "github.com/cilium/cilium/pkg/loadbalancer/reconciler"
	"github.com/cilium/cilium/pkg/loadbalancer/redirectpolicy"
	"github.com/cilium/cilium/pkg/loadbalancer/reflectors"
	"github.com/cilium/cilium/pkg/loadbalancer/writer"
	"github.com/cilium/cilium/pkg/maglev"
	"github.com/cilium/cilium/pkg/maps/registry"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/source"
)

var (
	nodePortAddrs = []netip.Addr{
		netip.MustParseAddr("10.0.0.3"),
		netip.MustParseAddr("2002::1"),
	}

	maglevConfig, _ = maglev.UserConfig{
		TableSize: 1021,
		HashSeed:  maglev.DefaultHashSeed,
	}.ToConfig()
)

func testHive(lbConfig loadbalancer.Config,
	services chan resource.Event[*slim_corev1.Service],
	endpoints chan resource.Event[*k8s.Endpoints],
	serviceMatcherLRPEnabled bool,
	writerPtr **writer.Writer,
	db **statedb.DB,
	bo **lbreconciler.BPFOps,
	clientPtr **k8sClient.FakeClientset,
	podTablePtr *statedb.Table[k8sTables.LocalPod],
	lrpTablePtr *statedb.Table[*redirectpolicy.LocalRedirectPolicy],
) *hive.Hive {
	extConfig := loadbalancer.ExternalConfig{
		ZoneMapper: &option.DaemonConfig{},
		EnableIPv4: true,
		EnableIPv6: true,
	}

	lrpCells := []cell.Cell{}
	if serviceMatcherLRPEnabled {
		lrpCells = append(lrpCells,
			redirectpolicy.Cell,
			cell.Provide(func() redirectpolicy.TestSkipLBMap { return &noopSkipLBMap{} }),
			cell.Invoke(func(lrps statedb.Table[*redirectpolicy.LocalRedirectPolicy]) {
				*lrpTablePtr = lrps
			}),
		)
	}

	h := hive.New(
		cell.Module(
			"loadbalancer-test",
			"Test module",

			k8sClient.FakeClientCell(),
			node.LocalNodeStoreTestCell,

			cell.Provide(
				func() cmtypes.ClusterInfo {
					return cmtypes.ClusterInfo{}
				},
				func() loadbalancer.Config {
					return lbConfig
				},
				func() loadbalancer.ExternalConfig { return extConfig },
				func() *loadbalancer.TestConfig { return &loadbalancer.TestConfig{} },
				func() *option.DaemonConfig { return &option.DaemonConfig{} },

				func(lc cell.Lifecycle) (*maglev.Maglev, maglev.Config) {
					m := maglev.New(maglevConfig, lc)
					return m, maglevConfig
				},

				func() (<-chan resource.Event[*slim_corev1.Service], <-chan resource.Event[*k8s.Endpoints]) {
					return services, endpoints
				},
				reflectors.EventStreamForBenchmark,
			),

			k8sTables.PodTableCell,
			cell.Group(lrpCells...),

			cell.Invoke(func(db_ *statedb.DB, w *writer.Writer, bo_ *lbreconciler.BPFOps, client *k8sClient.FakeClientset, pods statedb.Table[k8sTables.LocalPod]) {
				*db = db_
				*writerPtr = w
				*bo = bo_
				*clientPtr = client
				*podTablePtr = pods
			}),

			writer.Cell,
			cell.Invoke(reflectors.RegisterK8sReflector),
			lbreconciler.Cell,
			metrics.Cell,
			registry.Cell,
			lbmaps.Cell,
			cell.Provide(reflectors.NetnsCookieSupportFunc),

			cell.Provide(
				tables.NewNodeAddressTable,
				statedb.RWTable[tables.NodeAddress].ToTable,
				source.NewSources,
			),
			cell.Invoke(func(db *statedb.DB, nodeAddrs statedb.RWTable[tables.NodeAddress]) {
				txn := db.WriteTxn(nodeAddrs)
				for _, addr := range nodePortAddrs {
					nodeAddrs.Insert(txn, tables.NodeAddress{
						Addr:       addr,
						NodePort:   true,
						Primary:    true,
						DeviceName: "eth0",
					})
					nodeAddrs.Insert(txn, tables.NodeAddress{
						Addr:       addr,
						NodePort:   true,
						Primary:    true,
						DeviceName: "eth0",
					})
				}
				txn.Commit()
			}),
		),
	)
	if serviceMatcherLRPEnabled {
		h.Viper().Set(redirectpolicy.EnableLocalRedirectPolicyName, true)
	}
	return h
}

// noopSkipLBMap keeps the benchmark focused on control-plane reconciliation by
// satisfying the LRP skip-LB dependency without interacting with a BPF map.
type noopSkipLBMap struct{}

func (*noopSkipLBMap) AddLB4(uint64, netip.Addr, uint16) error { return nil }
func (*noopSkipLBMap) AddLB6(uint64, netip.Addr, uint16) error { return nil }
func (*noopSkipLBMap) DeleteLB4(*lbmaps.SkipLB4Key) error      { return nil }
func (*noopSkipLBMap) DeleteLB6(*lbmaps.SkipLB6Key) error      { return nil }

func (*noopSkipLBMap) AllLB4() iter.Seq2[*lbmaps.SkipLB4Key, *lbmaps.SkipLB4Value] {
	return func(func(*lbmaps.SkipLB4Key, *lbmaps.SkipLB4Value) bool) {}
}

func (*noopSkipLBMap) AllLB6() iter.Seq2[*lbmaps.SkipLB6Key, *lbmaps.SkipLB6Value] {
	return func(func(*lbmaps.SkipLB6Key, *lbmaps.SkipLB6Value) bool) {}
}
