// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package datapath

import (
	"log"
	"path/filepath"

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
	"github.com/cilium/cilium/pkg/datapath/linux/utime"
	"github.com/cilium/cilium/pkg/datapath/tables"
	"github.com/cilium/cilium/pkg/datapath/tunnel"
	"github.com/cilium/cilium/pkg/datapath/types"
	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/maps"
	"github.com/cilium/cilium/pkg/maps/eventsmap"
	"github.com/cilium/cilium/pkg/maps/nodemap"
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
	tables.NodeAddressingCell,

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

	cell.Provide(func(dp types.Datapath) types.NodeIDHandler {
		return dp.NodeIDs()
	}),

	// DevicesController manages the devices and routes tables
	linuxdatapath.DevicesControllerCell,
	cell.Provide(func(cfg *option.DaemonConfig) linuxdatapath.DevicesConfig {
		// Provide the configured devices to the devices controller.
		// This is temporary until DevicesController takes ownership of the
		// device-related configuration options.
		return linuxdatapath.DevicesConfig{
			Devices: cfg.GetDevices(),
		}
	}),

	// Synchronizes the userspace ipcache with the corresponding BPF map.
	ipcache.Cell,
)

func newWireguardAgent(lc cell.Lifecycle) *wg.Agent {
	var wgAgent *wg.Agent
	if option.Config.EnableWireguard {
		if option.Config.EnableIPSec {
			log.Fatalf("WireGuard (--%s) cannot be used with IPsec (--%s)",
				option.EnableWireguard, option.EnableIPSecName)
		}

		var err error
		privateKeyPath := filepath.Join(option.Config.StateDir, wgTypes.PrivKeyFilename)
		wgAgent, err = wg.NewAgent(privateKeyPath)
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
	datapathConfig := linuxdatapath.DatapathConfiguration{
		HostDevice:   defaults.HostDevice,
		TunnelDevice: params.TunnelConfig.DeviceName(),
		ProcFs:       option.Config.ProcFs,
	}

	datapath := linuxdatapath.NewDatapath(linuxdatapath.DatapathParams{
		ConfigWriter:   params.ConfigWriter,
		RuleManager:    params.IptablesManager,
		WGAgent:        params.WgAgent,
		NodeMap:        params.NodeMap,
		NodeAddressing: params.NodeAddressing,
		BWManager:      params.BandwidthManager,
	}, datapathConfig)

	params.LC.Append(cell.Hook{
		OnStart: func(cell.HookContext) error {
			datapath.NodeIDs().RestoreNodeIDs()
			return nil
		},
	})

	return datapath
}

type datapathParams struct {
	cell.In

	LC      cell.Lifecycle
	WgAgent *wg.Agent

	// Force map initialisation before loader. You should not use these otherwise.
	// Some of the entries in this slice may be nil.
	BpfMaps []bpf.BpfMap `group:"bpf-maps"`

	NodeMap nodemap.Map

	NodeAddressing types.NodeAddressing

	// Depend on DeviceManager to ensure devices have been resolved.
	// This is required until option.Config.GetDevices() has been removed and
	// uses of it converted to Table[Device].
	DeviceManager *linuxdatapath.DeviceManager

	BandwidthManager types.BandwidthManager

	ModulesManager *modules.Manager

	IptablesManager *iptables.Manager

	ConfigWriter types.ConfigWriter

	TunnelConfig tunnel.Config
}
