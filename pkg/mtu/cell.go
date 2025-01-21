// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package mtu

import (
	"log/slog"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/cilium/statedb"
	"github.com/spf13/pflag"

	"github.com/cilium/cilium/daemon/cmd/cni"
	"github.com/cilium/cilium/daemon/k8s"
	"github.com/cilium/cilium/pkg/datapath/tables"
	"github.com/cilium/cilium/pkg/datapath/tunnel"
	"github.com/cilium/cilium/pkg/datapath/types"
	"github.com/cilium/cilium/pkg/option"
)

var Cell = cell.Module(
	"mtu",
	"MTU discovery",

	cell.ProvidePrivate(newTable),
	cell.Provide(
		statedb.RWTable[RouteMTU].ToTable,
		newForCell,
	),
	cell.Invoke(newEndpointUpdater),
	cell.Config(defaultConfig),
)

type MTU interface {
	GetDeviceMTU() int
	GetRouteMTU() int
	GetRoutePostEncryptMTU() int
	IsEnableRouteMTUForCNIChaining() bool
}

func newTable(db *statedb.DB) (statedb.RWTable[RouteMTU], error) {
	tbl, err := NewMTUTable()
	if err != nil {
		return nil, err
	}

	if err := db.RegisterTable(tbl); err != nil {
		return nil, err
	}

	return tbl, nil
}

type mtuParams struct {
	cell.In

	IPsec        types.IPsecKeyCustodian
	CNI          cni.CNIConfigManager
	TunnelConfig tunnel.Config

	DB              *statedb.DB
	MTUTable        statedb.RWTable[RouteMTU]
	Devices         statedb.Table[*tables.Device]
	JobRegistry     job.Registry
	Health          cell.Health
	Log             *slog.Logger
	DaemonConfig    *option.DaemonConfig
	LocalCiliumNode k8s.LocalCiliumNodeResource

	Config Config
}

type Config struct {
	// Enable route MTU for pod netns when CNI chaining is used
	EnableRouteMTUForCNIChaining bool
}

var defaultConfig = Config{
	EnableRouteMTUForCNIChaining: false,
}

func (c Config) Flags(flags *pflag.FlagSet) {
	flags.Bool("enable-route-mtu-for-cni-chaining", c.EnableRouteMTUForCNIChaining, "Enable route MTU for pod netns when CNI chaining is used")
}

func newForCell(lc cell.Lifecycle, p mtuParams, cc Config) (MTU, error) {
	c := &Configuration{}
	group := p.JobRegistry.NewGroup(p.Health)
	lc.Append(group)
	lc.Append(cell.Hook{
		OnStart: func(ctx cell.HookContext) error {
			vxlanOverIPv6 := !option.Config.EnableIPv4 && option.Config.RoutingMode == option.RoutingModeTunnel
			*c = NewConfiguration(
				p.IPsec.AuthKeySize(),
				option.Config.EnableIPSec,
				p.TunnelConfig.ShouldAdaptMTU(),
				option.Config.EnableWireguard,
				vxlanOverIPv6,
			)

			configuredMTU := option.Config.MTU
			if mtu := p.CNI.GetMTU(); mtu > 0 {
				configuredMTU = mtu
				p.Log.Info("Overwriting MTU based on CNI configuration", "mtu", configuredMTU)
			}

			if configuredMTU == 0 {
				mgr := &MTUManager{
					mtuParams:     p,
					Config:        c,
					localNodeInit: make(chan struct{}),
				}

				group.Add(job.OneShot("mtu-updater", mgr.Updater))
				if mgr.needLocalCiliumNode() {
					group.Add(job.Observer("local-cilium-node-observer", mgr.observeLocalCiliumNode, p.LocalCiliumNode))
				}
			} else {
				p.Log.Info("Using configured MTU", "mtu", configuredMTU)

				txn := p.DB.WriteTxn(p.MTUTable)
				defer txn.Abort()

				rmtu := c.Calculate(configuredMTU)

				rmtu.Prefix = DefaultPrefixV4
				_, _, err := p.MTUTable.Insert(txn, rmtu)
				if err != nil {
					return err
				}

				rmtu.Prefix = DefaultPrefixV6
				_, _, err = p.MTUTable.Insert(txn, rmtu)
				if err != nil {
					return err
				}

				txn.Commit()
			}

			return nil
		},
	})

	return &LatestMTUGetter{
		tbl:                            p.MTUTable,
		db:                             p.DB,
		isEnableRouteMTUForCNIChaining: cc.EnableRouteMTUForCNIChaining,
	}, nil
}

var _ MTU = (*LatestMTUGetter)(nil)

type LatestMTUGetter struct {
	tbl                            statedb.Table[RouteMTU]
	db                             *statedb.DB
	isEnableRouteMTUForCNIChaining bool
}

func (m *LatestMTUGetter) GetDeviceMTU() int {
	rtx := m.db.ReadTxn()
	mtu, _, _ := m.tbl.Get(rtx, MTURouteIndex.Query(DefaultPrefixV4))
	return mtu.DeviceMTU
}

func (m *LatestMTUGetter) GetRouteMTU() int {
	rtx := m.db.ReadTxn()
	mtu, _, _ := m.tbl.Get(rtx, MTURouteIndex.Query(DefaultPrefixV4))
	return mtu.RouteMTU
}

func (m *LatestMTUGetter) GetRoutePostEncryptMTU() int {
	rtx := m.db.ReadTxn()
	mtu, _, _ := m.tbl.Get(rtx, MTURouteIndex.Query(DefaultPrefixV4))
	return mtu.RoutePostEncryptMTU
}

func (m *LatestMTUGetter) IsEnableRouteMTUForCNIChaining() bool {
	return m.isEnableRouteMTUForCNIChaining
}
