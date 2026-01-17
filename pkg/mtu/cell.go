// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package mtu

import (
	"fmt"
	"log/slog"
	"strconv"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/cilium/statedb"
	"github.com/spf13/pflag"

	"github.com/cilium/cilium/daemon/cmd/cni"
	"github.com/cilium/cilium/daemon/k8s"
	"github.com/cilium/cilium/pkg/datapath/tables"
	"github.com/cilium/cilium/pkg/datapath/tunnel"
	"github.com/cilium/cilium/pkg/datapath/types"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/option"
	wgTypes "github.com/cilium/cilium/pkg/wireguard/types"
)

var Cell = cell.Module(
	"mtu",
	"MTU discovery",

	cell.ProvidePrivate(NewMTUTable),
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
	// PacketizationLayerPMTUDMode returns valid plpmtud mode as string (empty means: do not set).
	PacketizationLayerPMTUDMode() string
}

type mtuParams struct {
	cell.In

	IPsec        types.IPsecAgent
	CNI          cni.CNIConfigManager
	TunnelConfig tunnel.Config

	DB              *statedb.DB
	MTUTable        statedb.RWTable[RouteMTU]
	Devices         statedb.Table[*tables.Device]
	JobGroup        job.Group
	Log             *slog.Logger
	DaemonConfig    *option.DaemonConfig
	LocalCiliumNode k8s.LocalCiliumNodeResource
	WgConfig        wgTypes.WireguardConfig

	Config Config
}

type Config struct {
	// Enable route MTU for pod netns when CNI chaining is used
	EnableRouteMTUForCNIChaining bool
	MTU                          int
	// PacketizationLayerPMTUDMode configures kernel packetization layer path mtu discovery on Pod netns.
	PacketizationLayerPMTUDMode string
}

var defaultConfig = Config{
	EnableRouteMTUForCNIChaining: false,
	MTU:                          0,
	PacketizationLayerPMTUDMode:  "1",
}

func (c Config) Flags(flags *pflag.FlagSet) {
	flags.Bool("enable-route-mtu-for-cni-chaining", c.EnableRouteMTUForCNIChaining, "Enable route MTU for pod netns when CNI chaining is used")
	flags.Int("mtu", c.MTU, "Overwrite auto-detected MTU of underlying network")
	flags.String("packetization-layer-pmtud-mode", c.PacketizationLayerPMTUDMode, "Enables kernel packetization layer path mtu discovery on Pod netns (if empty will use host setting)")
}

func parsePLPMTUDMode(cc Config) error {
	val, err := strconv.Atoi(cc.PacketizationLayerPMTUDMode)
	if err != nil {
		return fmt.Errorf("packetization-layer-pmtud-mode value %q must be empty or integer: %w", val, err)
	}

	if val < 0 || val > 2 {
		return fmt.Errorf("invalid packetization-layer-pmtud-mode value (must be either empty or {0,1,2}")
	}
	return nil
}

func newForCell(lc cell.Lifecycle, p mtuParams, cc Config) (MTU, error) {
	if err := parsePLPMTUDMode(cc); err != nil {
		return nil, err
	}

	c := &Configuration{}
	lc.Append(cell.Hook{
		OnStart: func(ctx cell.HookContext) error {
			tunnelOverIPv6 := option.Config.RoutingMode == option.RoutingModeTunnel &&
				p.TunnelConfig.UnderlayProtocol() == tunnel.IPv6
			*c = NewConfiguration(
				p.IPsec.AuthKeySize(),
				p.IPsec.Enabled(),
				p.TunnelConfig.ShouldAdaptMTU(),
				p.WgConfig.Enabled(),
				tunnelOverIPv6,
			)

			configuredMTU := cc.MTU
			if mtu := p.CNI.GetMTU(); mtu > 0 {
				configuredMTU = mtu
				p.Log.Info("Overwriting MTU based on CNI configuration", logfields.MTU, configuredMTU)
			}

			if configuredMTU == 0 {
				mgr := &MTUManager{
					mtuParams:     p,
					Config:        c,
					localNodeInit: make(chan struct{}),
				}

				p.JobGroup.Add(job.OneShot("mtu-updater", mgr.Updater))
				if mgr.needLocalCiliumNode() {
					p.JobGroup.Add(job.Observer("local-cilium-node-observer", mgr.observeLocalCiliumNode, p.LocalCiliumNode))
				}
			} else {
				p.Log.Info("Using configured MTU", logfields.MTU, configuredMTU)

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
		packetizationLayerPMTUDMode:    cc.PacketizationLayerPMTUDMode,
	}, nil
}

var _ MTU = (*LatestMTUGetter)(nil)

type LatestMTUGetter struct {
	tbl                            statedb.Table[RouteMTU]
	db                             *statedb.DB
	isEnableRouteMTUForCNIChaining bool
	packetizationLayerPMTUDMode    string
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

func (m *LatestMTUGetter) PacketizationLayerPMTUDMode() string {
	fmt.Println("[tom-debug] plmpmtud-mode->", m.packetizationLayerPMTUDMode)
	return m.packetizationLayerPMTUDMode
}
