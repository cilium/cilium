// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package datapath

import (
	"fmt"
	"log/slog"
	"path/filepath"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/cilium/statedb"

	"github.com/cilium/cilium/pkg/act"
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
	"github.com/cilium/cilium/pkg/datapath/linux/sysctl"
	"github.com/cilium/cilium/pkg/datapath/linux/utime"
	"github.com/cilium/cilium/pkg/datapath/loader"
	"github.com/cilium/cilium/pkg/datapath/node"
	"github.com/cilium/cilium/pkg/datapath/orchestrator"
	"github.com/cilium/cilium/pkg/datapath/prefilter"
	"github.com/cilium/cilium/pkg/datapath/tables"
	"github.com/cilium/cilium/pkg/datapath/tunnel"
	"github.com/cilium/cilium/pkg/datapath/types"
	"github.com/cilium/cilium/pkg/datapath/xdp"
	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/maglev"
	"github.com/cilium/cilium/pkg/maps"
	"github.com/cilium/cilium/pkg/maps/eventsmap"
	"github.com/cilium/cilium/pkg/maps/lbmap"
	monitorAgent "github.com/cilium/cilium/pkg/monitor/agent"
	"github.com/cilium/cilium/pkg/mtu"
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

	// Manages Cilium-specific iptables rules.
	iptables.Cell,

	cell.Invoke(initDatapath),

	cell.Provide(newWireguardAgent),

	cell.Provide(func(lbConfig loadbalancer.Config, maglev *maglev.Maglev, logger *slog.Logger) types.LBMap {
		if lbConfig.EnableExperimentalLB {
			// The experimental control-plane comes with its own LBMap implementation.
			return nil
		}
		return lbmap.New(logger, lbConfig, maglev)
	}),

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

	// Synchronizes load-balancing backends with the neighbor table.
	linuxdatapath.BackendNeighborSyncCell,

	// Synchronizes the userspace ipcache with the corresponding BPF map.
	ipcache.Cell,

	// Provides the loader, which compiles and loads the datapath programs.
	loader.Cell,

	// Provides prefilter, a means of configuring XDP pre-filters for DDoS-mitigation.
	prefilter.Cell,

	// XDP cell provides modularized XDP enablement.
	xdp.Cell,

	// Provides node handler, which handles node events.
	cell.Provide(linuxdatapath.NewNodeHandler),
	cell.Provide(node.NewNodeIDApiHandler),

	// Provides Active Connection Tracking metrics based on counts of
	// opened (from BPF ACT map), closed (from BPF ACT map), and failed
	// connections (from ctmap's GC).
	act.Cell,

	// Provides a cache of link names to ifindex mappings
	link.Cell,
)

func newWireguardAgent(rootLogger *slog.Logger, lc cell.Lifecycle, sysctl sysctl.Sysctl, health cell.Health, registry job.Registry, db *statedb.DB, mtuTable statedb.Table[mtu.RouteMTU]) *wg.Agent {
	var wgAgent *wg.Agent
	if option.Config.EnableWireguard {
		if option.Config.EnableIPSec {
			logging.Fatal(rootLogger, fmt.Sprintf("WireGuard (--%s) cannot be used with IPsec (--%s)",
				option.EnableWireguard, option.EnableIPSecName))
		}

		jobGroup := registry.NewGroup(health, lc)

		var err error
		privateKeyPath := filepath.Join(option.Config.StateDir, wgTypes.PrivKeyFilename)
		wgAgent, err = wg.NewAgent(rootLogger, privateKeyPath, sysctl, jobGroup, db, mtuTable)
		if err != nil {
			logging.Fatal(rootLogger, fmt.Sprintf("failed to initialize WireGuard: %s", err))
		}

		lc.Append(wgAgent)
	} else {
		// Delete WireGuard device from previous run (if such exists)
		link.DeleteByName(wgTypes.IfaceName)
	}
	return wgAgent
}

func initDatapath(rootLogger *slog.Logger, lifecycle cell.Lifecycle) {
	lifecycle.Append(cell.Hook{
		OnStart: func(cell.HookContext) error {
			if err := linuxdatapath.CheckRequirements(rootLogger); err != nil {
				return fmt.Errorf("requirements failed: %w", err)
			}

			return nil
		},
	})
}
