// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package datapath

import (
	"log"
	"path/filepath"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/datapath/iptables"
	"github.com/cilium/cilium/pkg/datapath/link"
	linuxdatapath "github.com/cilium/cilium/pkg/datapath/linux"
	"github.com/cilium/cilium/pkg/datapath/linux/utime"
	"github.com/cilium/cilium/pkg/datapath/types"
	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/hive/cell"
	ipcache "github.com/cilium/cilium/pkg/ipcache/types"
	"github.com/cilium/cilium/pkg/maps"
	"github.com/cilium/cilium/pkg/maps/eventsmap"
	"github.com/cilium/cilium/pkg/maps/nodemap"
	monitorAgent "github.com/cilium/cilium/pkg/monitor/agent"
	"github.com/cilium/cilium/pkg/option"
	wg "github.com/cilium/cilium/pkg/wireguard/agent"
	wgTypes "github.com/cilium/cilium/pkg/wireguard/types"
)

// Datapath provides the privileged operations to apply control-plane
// decision to the kernel.
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

	cell.Provide(
		newWireguardAgent,
		newDatapath,
	),

	cell.Provide(func(dp types.Datapath) ipcache.NodeIDHandler {
		return dp.NodeIDs()
	}),
)

func newWireguardAgent(lc hive.Lifecycle) *wg.Agent {
	var wgAgent *wg.Agent
	if option.Config.EnableWireguard {
		if option.Config.EnableIPSec {
			log.Fatalf("Wireguard (--%s) cannot be used with IPSec (--%s)",
				option.EnableWireguard, option.EnableIPSecName)
		}

		var err error
		privateKeyPath := filepath.Join(option.Config.StateDir, wgTypes.PrivKeyFilename)
		wgAgent, err = wg.NewAgent(privateKeyPath)
		if err != nil {
			log.Fatalf("failed to initialize wireguard: %s", err)
		}

		lc.Append(hive.Hook{
			OnStop: func(hive.HookContext) error {
				wgAgent.Close()
				return nil
			},
		})
	} else {
		// Delete wireguard device from previous run (if such exists)
		link.DeleteByName(wgTypes.IfaceName)
	}
	return wgAgent
}

func newDatapath(params datapathParams) types.Datapath {
	datapathConfig := linuxdatapath.DatapathConfiguration{
		HostDevice: defaults.HostDevice,
		ProcFs:     option.Config.ProcFs,
	}

	iptablesManager := &iptables.IptablesManager{}

	params.LC.Append(hive.Hook{
		OnStart: func(hive.HookContext) error {
			// FIXME enableIPForwarding should not live here
			if err := enableIPForwarding(); err != nil {
				log.Fatalf("enabling IP forwarding via sysctl failed: %s", err)
			}

			iptablesManager.Init()
			return nil
		}})

	datapath := linuxdatapath.NewDatapath(datapathConfig, iptablesManager, params.WgAgent, params.NodeMap)

	params.LC.Append(hive.Hook{
		OnStart: func(hive.HookContext) error {
			datapath.NodeIDs().RestoreNodeIDs()
			return nil
		},
	})

	return datapath
}

type datapathParams struct {
	cell.In

	LC      hive.Lifecycle
	WgAgent *wg.Agent

	// Force map initialisation before loader. You should not use these otherwise.
	// Some of the entries in this slice may be nil.
	BpfMaps []bpf.BpfMap `group:"bpf-maps"`

	NodeMap nodemap.Map
}
