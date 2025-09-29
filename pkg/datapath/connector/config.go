// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package connector

import (
	"fmt"
	"log/slog"
	"math"

	"github.com/cilium/hive/cell"

	"github.com/cilium/cilium/pkg/datapath/linux/safenetlink"
	"github.com/cilium/cilium/pkg/datapath/tunnel"
	"github.com/cilium/cilium/pkg/datapath/types"
	"github.com/cilium/cilium/pkg/defaults"
	wgTypes "github.com/cilium/cilium/pkg/wireguard/types"
)

type connectorParams struct {
	cell.In

	Lifecycle    cell.Lifecycle
	Log          *slog.Logger
	UserConfig   types.ConnectorUserConfig
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
	wgHeadroom, wgTailroom, err := p.WgAgent.IfaceBufferMargins()
	if err != nil {
		return err
	}

	tunnelHeadroom, tunnelTailroom, err := getTunnelBufferMargins(p.TunnelConfig.EncapProtocol())
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

	// Cache the values
	cc.podDeviceHeadroom = uint16(totalHeadroom)
	cc.podDeviceTailroom = uint16(totalTailroom)
	return nil
}

// getTunnelBufferMargins returns the buffer margins for the underlying tunnel
// device, if enabled. This is located here, and not with the tunnel code, to
// avoid a circular go import.
func getTunnelBufferMargins(mode tunnel.EncapProtocol) (uint16, uint16, error) {
	var deviceName string

	switch mode {
	case tunnel.Geneve:
		deviceName = defaults.GeneveDevice
	case tunnel.VXLAN:
		deviceName = defaults.VxlanDevice
	default:
		// No tunnel, no attributes
		return 0, 0, nil
	}

	device, err := safenetlink.LinkByName(deviceName)
	if err != nil {
		return 0, 0, err
	}

	return device.Attrs().Headroom, device.Attrs().Tailroom, nil
}
