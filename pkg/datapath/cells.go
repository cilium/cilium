// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package datapath

import (
	"log"
	"path/filepath"

	"github.com/cilium/cilium/pkg/datapath/iptables"
	"github.com/cilium/cilium/pkg/datapath/link"
	linuxdatapath "github.com/cilium/cilium/pkg/datapath/linux"
	"github.com/cilium/cilium/pkg/datapath/types"
	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/hive/cell"
	ipcache "github.com/cilium/cilium/pkg/ipcache/types"
	"github.com/cilium/cilium/pkg/option"
	wg "github.com/cilium/cilium/pkg/wireguard/agent"
	wgTypes "github.com/cilium/cilium/pkg/wireguard/types"
)

// Datapath provides the privileged operations to apply control-plane
// decision to the kernel.
var Cell = cell.Module(
	"datapath",
	"Datapath",

	cell.Provide(
		newWireguardAgent,
		newDatapath,
	),

	cell.Provide(func(dp types.Datapath) ipcache.NodeHandler {
		return dp.Node()
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

func newDatapath(lc hive.Lifecycle, wgAgent *wg.Agent) types.Datapath {
	datapathConfig := linuxdatapath.DatapathConfiguration{
		HostDevice: defaults.HostDevice,
		ProcFs:     option.Config.ProcFs,
	}

	iptablesManager := &iptables.IptablesManager{}

	lc.Append(hive.Hook{
		OnStart: func(hive.HookContext) error {
			// FIXME enableIPForwarding should not live here
			if err := enableIPForwarding(); err != nil {
				log.Fatalf("enabling IP forwarding via sysctl failed: %s", err)
			}

			iptablesManager.Init()
			return nil
		}})

	return linuxdatapath.NewDatapath(datapathConfig, iptablesManager, wgAgent)
}
