// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package datapath

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"

	"github.com/cilium/cilium/pkg/act"
	"github.com/cilium/cilium/pkg/datapath/agentliveness"
	"github.com/cilium/cilium/pkg/datapath/garp"
	"github.com/cilium/cilium/pkg/datapath/ipcache"
	"github.com/cilium/cilium/pkg/datapath/iptables"
	"github.com/cilium/cilium/pkg/datapath/l2responder"
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
	"github.com/cilium/cilium/pkg/datapath/xdp"
	"github.com/cilium/cilium/pkg/loadbalancer/experimental"
	"github.com/cilium/cilium/pkg/maps"
	"github.com/cilium/cilium/pkg/maps/eventsmap"
	"github.com/cilium/cilium/pkg/maps/lbmap"
	monitorAgent "github.com/cilium/cilium/pkg/monitor/agent"
	"github.com/cilium/cilium/pkg/mtu"
	nodeManager "github.com/cilium/cilium/pkg/node/manager"
	"github.com/cilium/cilium/pkg/testutils/mockmaps"
	wg "github.com/cilium/cilium/pkg/wireguard/agent"
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

	cell.Invoke(initDatapath),

	cell.Provide(func(expConfig experimental.Config) types.LBMap {
		if expConfig.EnableExperimentalLB {
			// The experimental control-plane is enabled. Use a fake LBMap
			// to effectively disable the other code paths writing to LBMaps.
			return mockmaps.NewLBMockMap()
		}

		return lbmap.New()
	}),

	// Wireguard agent
	wg.Cell,

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

	// XDP cell provides modularized XDP enablement.
	xdp.Cell,

	// Provides node handler, which handles node events.
	cell.Provide(linuxdatapath.NewNodeHandler),
	cell.Provide(node.NewNodeIDApiHandler),
	cell.Invoke(func(jg job.Group, h types.NodeHandler, nm nodeManager.NodeManager) {
		// FIXME: Subscribe() sends to an unbuffered channel, so one can only
		// subscribe when NodeManager is running. Rethink or just factor out the
		// Subscribe() altogether.
		jg.Add(job.OneShot("node-handler-subscribe",
			func(context.Context, cell.Health) error {
				nm.Subscribe(h)
				return nil
			}))
	}),
	linuxdatapath.NodeReconcilerCell,

	// Provides Active Connection Tracking metrics based on counts of
	// opened (from BPF ACT map), closed (from BPF ACT map), and failed
	// connections (from ctmap's GC).
	act.Cell,
)

func initDatapath(logger *slog.Logger, lifecycle cell.Lifecycle) {
	lifecycle.Append(cell.Hook{
		OnStart: func(cell.HookContext) error {
			if err := linuxdatapath.CheckRequirements(logger); err != nil {
				return fmt.Errorf("requirements failed: %w", err)
			}

			return nil
		},
	})
}
