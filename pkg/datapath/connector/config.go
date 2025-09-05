// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package connector

import (
	"fmt"
	"log/slog"
	"math"

	"github.com/cilium/hive/cell"

	datapathOption "github.com/cilium/cilium/pkg/datapath/option"
	"github.com/cilium/cilium/pkg/datapath/tunnel"
	"github.com/cilium/cilium/pkg/datapath/types"
	"github.com/cilium/cilium/pkg/option"
	wgTypes "github.com/cilium/cilium/pkg/wireguard/types"
)

type connectorParams struct {
	cell.In

	Lifecycle    cell.Lifecycle
	Log          *slog.Logger
	UserConfig   types.ConnectorUserConfig
	DaemonConfig *option.DaemonConfig
	WgAgent      wgTypes.WireguardAgent
	TunnelConfig tunnel.Config
}

// newConnectorConfig initialises a new ConnectorConfig object with default
// parameters. If EnableTunedBufferMargins is enabled, we register a callback
// with the Hive to detect necessary tuning parameters.
func newConnectorConfig(p connectorParams) (*ConnectorConfig, error) {
	cc := &ConnectorConfig{
		UserConfig:        p.UserConfig,
		podDeviceHeadroom: 0,
		podDeviceTailroom: 0,
	}

	if cc.UserConfig.EnableTunedBufferMargins {
		// At present, only netkit supports tuned buffer margins.
		switch p.DaemonConfig.DatapathMode {
		case datapathOption.DatapathModeNetkit, datapathOption.DatapathModeNetkitL2:
		default:
			return nil, fmt.Errorf("--%s is not supported with --%s=%s",
				types.EnableTunedBufferMarginsFlag,
				option.DatapathMode,
				p.DaemonConfig.DatapathMode)
		}

		// TODO: We need a way of validating that we can rely on the kernel
		// to report buffer margins via netlink generic attributes. If we can't
		// rely on the kernel here, we should probably error out in future.
		//
		// In an ideal world we'd have something like nk.SupportsScrub() in
		// the upstream netlink library, but that would need to be done at
		// a generic level and probably isn't acceptable to the maintainer.
		//
		// A better approach might be to just try create a dummy netkit
		// interface with some magic headroom value, and check we can read
		// it back.

		p.Lifecycle.Append(cell.Hook{
			OnStart: func(cell.HookContext) error {
				return generateConnectorConfig(p, cc)
			},
		})
	}

	return cc, nil
}

// generateConnectorConfig aims to calculate necessary tuning parameters for
// pod/workload-facing network device pairs.
func generateConnectorConfig(p connectorParams, cc *ConnectorConfig) error {
	if !cc.UserConfig.EnableTunedBufferMargins {
		return nil
	}

	wgHeadroom, wgTailroom, err := p.WgAgent.IfaceBufferMargins()
	if err != nil {
		return err
	}

	tunnelHeadroom, tunnelTailroom, err := p.TunnelConfig.DeviceBufferMargins()
	if err != nil {
		return err
	}

	// There's nothing technically stopping these discovered values from being
	// to be on the high end of the underlying storage type. When combined, they
	// may overflow, so look out for this.
	var totalHeadroom = uint32(wgHeadroom + tunnelHeadroom)
	if totalHeadroom > math.MaxUint16 {
		return fmt.Errorf("connector total headroom %d exceeds maximum value %d", totalHeadroom, math.MaxUint16)
	}
	var totalTailroom = uint32(wgTailroom + tunnelTailroom)
	if totalTailroom > math.MaxUint16 {
		return fmt.Errorf("connector total tailroom %d exeeds maximum value %d", totalHeadroom, math.MaxUint16)
	}

	cc.podDeviceHeadroom = uint16(totalHeadroom)
	cc.podDeviceTailroom = uint16(totalTailroom)
	return nil
}
