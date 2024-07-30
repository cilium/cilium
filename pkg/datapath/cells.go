// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package datapath

import (
	"fmt"
	"log"
	"log/slog"
	"path/filepath"

	"github.com/cilium/hive/cell"
	"github.com/cilium/statedb"

	"github.com/cilium/cilium/pkg/act"
	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/datapath/agentliveness"
	"github.com/cilium/cilium/pkg/datapath/garp"
	"github.com/cilium/cilium/pkg/datapath/ipcache"
	"github.com/cilium/cilium/pkg/datapath/iptables"
	"github.com/cilium/cilium/pkg/datapath/l2responder"
	"github.com/cilium/cilium/pkg/datapath/link"
	linuxdatapath "github.com/cilium/cilium/pkg/datapath/linux"
	"github.com/cilium/cilium/pkg/datapath/linux/bandwidth"
	"github.com/cilium/cilium/pkg/datapath/linux/bigtcp"
	dpcfg "github.com/cilium/cilium/pkg/datapath/linux/config"
	"github.com/cilium/cilium/pkg/datapath/linux/ipsec"
	"github.com/cilium/cilium/pkg/datapath/linux/modules"
	"github.com/cilium/cilium/pkg/datapath/linux/sysctl"
	"github.com/cilium/cilium/pkg/datapath/linux/utime"
	"github.com/cilium/cilium/pkg/datapath/loader"
	"github.com/cilium/cilium/pkg/datapath/node"
	"github.com/cilium/cilium/pkg/datapath/orchestrator"
	"github.com/cilium/cilium/pkg/datapath/prefilter"
	"github.com/cilium/cilium/pkg/datapath/tables"
	"github.com/cilium/cilium/pkg/datapath/tunnel"
	"github.com/cilium/cilium/pkg/datapath/types"
	"github.com/cilium/cilium/pkg/maps"
	"github.com/cilium/cilium/pkg/maps/eventsmap"
	"github.com/cilium/cilium/pkg/maps/nodemap"
	monitorAgent "github.com/cilium/cilium/pkg/monitor/agent"
	"github.com/cilium/cilium/pkg/mtu"
	nodeManager "github.com/cilium/cilium/pkg/node/manager"
	"github.com/cilium/cilium/pkg/option"
	wg "github.com/cilium/cilium/pkg/wireguard/agent"
	wgTypes "github.com/cilium/cilium/pkg/wireguard/types"
)

// Datapath provides the privileged operations to apply control-plane
// decision to the kernel.
//
// For integration testing a fake counterpart of this module is defined
// in pkg/datapath/fake/cells.go.
var Cell = cell.Module(
	"datapath",
	"Datapath",

	// Provides all BPF Map which are already provided by via hive cell.
	maps.Cell,

	// Utime synchronizes utime from userspace to datapath via configmap.Map.
	utime.Cell,

	// The cilium events map, used by the monitor agent.
	eventsmap.Cell,

	// The monitor agent, which multicasts cilium and agent events to its subscribers.
	monitorAgent.Cell,

	// The sysctl reconciler to read and write kernel sysctl parameters.
	sysctl.Cell,

	// The modules manager to search and load kernel modules.
	modules.Cell,

	// Manages Cilium-specific iptables rules.
	iptables.Cell,

	cell.Provide(
		newWireguardAgent,
		newDatapath,
	),

	// Provides the Table[NodeAddress] and the controller that populates it from Table[*Device]
	tables.NodeAddressCell,

	// Provides the legacy accessor for the above, the NodeAddressing interface.
	NodeAddressingCell,

	// Provides the DirectRoutingDevice selection logic.
	tables.DirectRoutingDeviceCell,

	// This cell periodically updates the agent liveness value in configmap.Map to inform
	// the datapath of the liveness of the agent.
	agentliveness.Cell,

	// The responder reconciler takes desired state about L3->L2 address translation responses and reconciles
	// it to the BPF L2 responder map.
	l2responder.Cell,

	// Gratuitous ARP event processor emits GARP packets on k8s pod creation events.
	garp.Cell,

	// This cell provides the object used to write the headers for datapath program types.
	dpcfg.Cell,

	// BIG TCP increases GSO/GRO limits when enabled.
	bigtcp.Cell,

	// Tunnel protocol configuration and alike.
	tunnel.Cell,

	// The bandwidth manager provides efficient EDT-based rate-limiting (on Linux).
	bandwidth.Cell,

	// IPsec cell provides the IPsecKeyCustodian.
	ipsec.Cell,

	// MTU provides the MTU configuration of the node.
	mtu.Cell,

	orchestrator.Cell,

	// DevicesController manages the devices and routes tables
	linuxdatapath.DevicesControllerCell,

	// Synchronizes the userspace ipcache with the corresponding BPF map.
	ipcache.Cell,

	// Provides the loader, which compiles and loads the datapath programs.
	loader.Cell,

	// Provides prefilter, a means of configuring XDP pre-filters for DDoS-mitigation.
	prefilter.Cell,

	// Provides node handler, which handles node events.
	cell.Provide(linuxdatapath.NewNodeHandler),
	cell.Provide(node.NewNodeIDApiHandler),

	// Provides Active Connection Tracking metrics based on counts of
	// opened (from BPF ACT map), closed (from BPF ACT map), and failed
	// connections (from ctmap's GC).
	act.Cell,
)

func newWireguardAgent(lc cell.Lifecycle, sysctl sysctl.Sysctl) *wg.Agent {
	var wgAgent *wg.Agent
	if option.Config.EnableWireguard {
		if option.Config.EnableIPSec {
			log.Fatalf("WireGuard (--%s) cannot be used with IPsec (--%s)",
				option.EnableWireguard, option.EnableIPSecName)
		}

		var err error
		privateKeyPath := filepath.Join(option.Config.StateDir, wgTypes.PrivKeyFilename)
		wgAgent, err = wg.NewAgent(privateKeyPath, sysctl)
		if err != nil {
			log.Fatalf("failed to initialize WireGuard: %s", err)
		}

		lc.Append(cell.Hook{
			OnStop: func(cell.HookContext) error {
				wgAgent.Close()
				return nil
			},
		})
	} else {
		// Delete WireGuard device from previous run (if such exists)
		link.DeleteByName(wgTypes.IfaceName)
	}
	return wgAgent
}

func newDatapath(params datapathParams) types.Datapath {
	datapath := linuxdatapath.NewDatapath(linuxdatapath.DatapathParams{
		ConfigWriter:   params.ConfigWriter,
		RuleManager:    params.IptablesManager,
		WGAgent:        params.WgAgent,
		NodeMap:        params.NodeMap,
		NodeAddressing: params.NodeAddressing,
		BWManager:      params.BandwidthManager,
		Loader:         params.Loader,
		NodeManager:    params.NodeManager,
		DB:             params.DB,
		Devices:        params.Devices,
		Orchestrator:   params.Orchestrator,
		NodeHandler:    params.NodeHandler,
		NodeNeighbors:  params.NodeNeighbors,
	})

	params.LC.Append(cell.Hook{
		OnStart: func(cell.HookContext) error {
			if err := linuxdatapath.CheckRequirements(params.Log); err != nil {
				return fmt.Errorf("requirements failed: %w", err)
			}

			params.NodeIDHandler.RestoreNodeIDs()
			return nil
		},
	})

	return datapath
}

type datapathParams struct {
	cell.In

	Log *slog.Logger

	LC      cell.Lifecycle
	WgAgent *wg.Agent

	// Force map initialisation before loader. You should not use these otherwise.
	// Some of the entries in this slice may be nil.
	BpfMaps []bpf.BpfMap `group:"bpf-maps"`

	NodeMap nodemap.MapV2

	NodeAddressing types.NodeAddressing

	DB      *statedb.DB
	Devices statedb.Table[*tables.Device]

	BandwidthManager types.BandwidthManager

	ModulesManager *modules.Manager

	IptablesManager *iptables.Manager

	ConfigWriter types.ConfigWriter

	TunnelConfig tunnel.Config

	Loader types.Loader

	NodeManager nodeManager.NodeManager

	Orchestrator types.Orchestrator

	NodeHandler types.NodeHandler

	NodeIDHandler types.NodeIDHandler

	NodeNeighbors types.NodeNeighbors
}
