// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package agent

import (
	"context"
	"fmt"
	"path/filepath"

	"go.uber.org/fx"

	"github.com/cilium/cilium/pkg/datapath"
	"github.com/cilium/cilium/pkg/datapath/link"
	"github.com/cilium/cilium/pkg/ipcache"
	"github.com/cilium/cilium/pkg/mtu"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/wireguard/types"
)

var (
	Module = fx.Module(
		"wireguard",
		fx.Provide(newWireguardAgent),
		fx.Invoke(initWireguardAgent),
	)
)

func newWireguardAgent(lc fx.Lifecycle, config *option.DaemonConfig) (*Agent, datapath.WireguardAgent, error) {
	if !config.EnableWireguard {
		// Delete wireguard device from previous run (if such exists)
		link.DeleteByName(types.IfaceName)
		return nil, nil, nil
	}

	switch {
	case config.EnableIPSec:
		return nil, nil, fmt.Errorf("Wireguard (--%s) cannot be used with IPSec (--%s)",
			option.EnableWireguard, option.EnableIPSecName)
	case config.EnableL7Proxy:
		return nil, nil, fmt.Errorf("Wireguard (--%s) is not compatible with L7 proxy (--%s)",
			option.EnableWireguard, option.EnableL7Proxy)
	}

	privateKeyPath := filepath.Join(config.StateDir, types.PrivKeyFilename)
	wgAgent, err := NewAgent(privateKeyPath)
	if err != nil {
		log.WithError(err).Fatal("Failed to initialize wireguard")
	}
	return wgAgent, wgAgent, nil
}

func initWireguardAgent(lc fx.Lifecycle, wgAgent *Agent, ipcache *ipcache.IPCache, mtuConfig mtu.Configuration) error {
	if wgAgent == nil {
		return nil
	}
	lc.Append(fx.Hook{
		OnStart: func(context.Context) error {
			if err := wgAgent.Init(ipcache, mtuConfig); err != nil {
				return fmt.Errorf("failed to initialize wireguard agent: %w", err)
			}
			if err := wgAgent.RestoreFinished(); err != nil {
				log.WithError(err).Error("Failed to set up wireguard peers")
			}
			return nil
		},
		OnStop: func(context.Context) error {
			return wgAgent.Close()
		},
	})
	return nil
}
