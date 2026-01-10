// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package connector

import (
	"log/slog"
	"math"

	"github.com/cilium/hive/cell"

	datapathOption "github.com/cilium/cilium/pkg/datapath/option"
	"github.com/cilium/cilium/pkg/datapath/tunnel"
	"github.com/cilium/cilium/pkg/datapath/types"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/option"
	wgTypes "github.com/cilium/cilium/pkg/wireguard/types"
)

// LinkConfig contains the GRO/GSO, MTU values and buffer margins to be configured on both sides of
// the created pair.
type LinkConfig struct {
	GROIPv6MaxSize int
	GSOIPv6MaxSize int

	GROIPv4MaxSize int
	GSOIPv4MaxSize int

	DeviceMTU      int
	DeviceHeadroom uint16
	DeviceTailroom uint16
}

// Connector configuration. As per BIGTCP, the values here will not be calculated
// until the Hive has started. This is necessary to allow other dependencies to
// setup their interfaces etc.
type ConnectorConfig struct {
	// podDeviceHeadroom tracks the desired headroom buffer margin for the
	// network device pair facing a workload.
	podDeviceHeadroom uint16

	// podDeviceTailroom tracks the desired tailroom buffer margin for the
	// network device pairs facing a workload.
	podDeviceTailroom uint16
}

func (cc *ConnectorConfig) GetPodDeviceHeadroom() uint16 {
	return cc.podDeviceHeadroom
}

func (cc *ConnectorConfig) GetPodDeviceTailroom() uint16 {
	return cc.podDeviceTailroom
}

type connectorParams struct {
	cell.In

	Lifecycle    cell.Lifecycle
	Log          *slog.Logger
	DaemonConfig *option.DaemonConfig
	Orchestrator types.Orchestrator
	WgAgent      wgTypes.WireguardAgent
	TunnelConfig tunnel.Config
}

// Returns true if we should actively try and align the connector's netdev buffer
// margins with that of the host's egress interfaces (e.g. tunnel, wireguard).
func useTunedBufferMargins(datapathMode string) bool {
	switch datapathMode {
	case datapathOption.DatapathModeNetkit, datapathOption.DatapathModeNetkitL2:
		return true
	}
	return false
}

// newConnectorConfig initialises a new ConnectorConfig object with default parameters.
func newConfig(p connectorParams) *ConnectorConfig {
	cc := &ConnectorConfig{}

	if useTunedBufferMargins(p.DaemonConfig.DatapathMode) {
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
				return generateConfig(p, cc)
			},
		})
	}

	return cc
}

// generateConfig aims to calculate necessary tuning parameters for pod/workload-facing
// network device pairs.
func generateConfig(p connectorParams, cc *ConnectorConfig) error {
	if !useTunedBufferMargins(p.DaemonConfig.DatapathMode) {
		return nil
	}

	// We must wait for the Orchestrator to signal that the datapath is initialised,
	// so that it has chance to create any tunneling devices. Otherwise, we'll fail
	// to query a device below and error out by accident.
	<-p.Orchestrator.DatapathInitialized()

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
	// may overflow a U16.
	var totalHeadroom = uint32(wgHeadroom) + uint32(tunnelHeadroom)
	if totalHeadroom > math.MaxUint16 {
		p.Log.Warn("Total calculated headroom would exceed maximum value, using default",
			logfields.DeviceHeadroom, totalHeadroom)
	} else {
		cc.podDeviceHeadroom = uint16(totalHeadroom)
	}
	var totalTailroom = uint32(wgTailroom) + uint32(tunnelTailroom)
	if totalTailroom > math.MaxUint16 {
		p.Log.Warn("Total calculated tailroom would exceed maximum value, using default",
			logfields.DeviceTailroom, totalTailroom)
	} else {
		cc.podDeviceTailroom = uint16(totalTailroom)
	}
	return nil
}
