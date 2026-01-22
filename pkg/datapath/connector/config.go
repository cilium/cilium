// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package connector

import (
	"fmt"
	"log/slog"
	"math"

	"github.com/cilium/hive/cell"
	"github.com/vishvananda/netlink"

	"github.com/cilium/cilium/pkg/datapath/linux/probes"
	"github.com/cilium/cilium/pkg/datapath/linux/safenetlink"
	"github.com/cilium/cilium/pkg/datapath/linux/sysctl"
	"github.com/cilium/cilium/pkg/datapath/tunnel"
	"github.com/cilium/cilium/pkg/datapath/types"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/option"
	wgTypes "github.com/cilium/cilium/pkg/wireguard/types"
)

// Connector configuration. As per BIGTCP, the values here will not be calculated
// until the Hive has started. This is necessary to allow other dependencies to
// setup their interfaces etc.
type ConnectorConfig struct {
	log          *slog.Logger
	wgAgent      wgTypes.WireguardAgent
	tunnelConfig tunnel.Config

	// podDeviceHeadroom tracks the desired headroom buffer margin for the
	// network device pair facing a workload.
	podDeviceHeadroom uint16

	// podDeviceTailroom tracks the desired tailroom buffer margin for the
	// network device pairs facing a workload.
	podDeviceTailroom uint16

	// configuredMode tracks the configured datapath mode of Cilium,
	// as specified by runtime configuration.
	configuredMode types.ConnectorMode

	// operationalMode tracks the operational datapath mode of Cilium,
	// which may differ from the configured datapath mode.
	operationalMode types.ConnectorMode
}

func (cc *ConnectorConfig) Reinitialize() error {
	return cc.calculateTunedBufferMargins()
}

func (cc *ConnectorConfig) GetPodDeviceHeadroom() uint16 {
	return cc.podDeviceHeadroom
}

func (cc *ConnectorConfig) GetPodDeviceTailroom() uint16 {
	return cc.podDeviceTailroom
}

func (cc *ConnectorConfig) GetConfiguredMode() types.ConnectorMode {
	return cc.configuredMode
}

func (cc *ConnectorConfig) GetOperationalMode() types.ConnectorMode {
	return cc.operationalMode
}

func (cc *ConnectorConfig) NewLinkPair(cfg types.LinkConfig, sysctl sysctl.Sysctl) (types.LinkPair, error) {
	return NewLinkPair(cc.log, cc.operationalMode, cfg, sysctl)
}

func (cc *ConnectorConfig) GetLinkCompatibility(ifName string) (types.ConnectorMode, bool, error) {
	link, err := safenetlink.LinkByName(ifName)
	if err != nil {
		return types.ConnectorModeUnspec, false, err
	}

	linkMode := types.GetConnectorModeByName(link.Type())

	// The netkit driver supports both L2 and L3 modes, which we can't identify
	// by the link type. If the link is operating at L2 mode, the above getter
	// will return the L3 type. Probe the netkit structure to fix this up.
	if linkMode == types.ConnectorModeNetkit {
		nk := link.(*netlink.Netkit)
		if nk.Mode == netlink.NETKIT_MODE_L2 {
			linkMode = types.ConnectorModeNetkitL2
		}
	}

	linkCompatible := cc.operationalMode == linkMode

	return linkMode, linkCompatible, nil
}

// Returns true if we should actively try and align the connector's netdev buffer
// margins with that of the host's egress interfaces (e.g. tunnel, wireguard).
func (cc *ConnectorConfig) useTunedBufferMargins() bool {
	return cc.operationalMode.IsNetkit()
}

type connectorParams struct {
	cell.In

	Lifecycle    cell.Lifecycle
	Log          *slog.Logger
	DaemonConfig *option.DaemonConfig
	WgAgent      wgTypes.WireguardAgent
	TunnelConfig tunnel.Config
}

func canUseNetkit(p connectorParams) error {
	if err := probes.HaveNetkit(); err != nil {
		return fmt.Errorf("netkit device probe failed, requires kernel 6.7.0+ and CONFIG_NETKIT")
	}

	// bpf.tproxy requires use of bpf_sk_assign() helper, which at the time of
	// writing can only be called from TC ingress. However, netkit programs
	// run at TC egress, so the helper returns -ENOTSUPP and tproxy cannot
	// assign skbs to proxy listener sockets.
	//
	// Until this is resolved we don't tolerate tproxy and netkit.
	//
	// GH issue: https://github.com/cilium/cilium/issues/39892

	if p.DaemonConfig.EnableBPFTProxy {
		return fmt.Errorf("netkit devices cannot be used with --%s=true", option.EnableBPFTProxy)
	}

	return nil
}

// newConnectorConfig initialises a new ConnectorConfig object with default parameters.
func newConfig(p connectorParams) (*ConnectorConfig, error) {
	var configuredMode, operationalMode types.ConnectorMode

	configuredMode = types.GetConnectorModeByName(p.DaemonConfig.DatapathMode)
	switch configuredMode {
	case types.ConnectorModeUnspec:
		return nil, fmt.Errorf("invalid datapath mode: %s", p.DaemonConfig.DatapathMode)

	case types.ConnectorModeAuto:
		if err := canUseNetkit(p); err != nil {
			p.Log.Warn("datapath autodiscovery failed, reverting from netkit to veth",
				logfields.Error, err)
			operationalMode = types.ConnectorModeVeth
		} else {
			operationalMode = types.ConnectorModeNetkit
		}

	case types.ConnectorModeNetkit, types.ConnectorModeNetkitL2:
		if err := canUseNetkit(p); err != nil {
			return nil, fmt.Errorf("netkit connector not available: %w", err)
		}

		fallthrough

	default:
		operationalMode = configuredMode
	}

	cc := &ConnectorConfig{
		log:             p.Log,
		wgAgent:         p.WgAgent,
		tunnelConfig:    p.TunnelConfig,
		configuredMode:  configuredMode,
		operationalMode: operationalMode,
	}

	// For netkit we enable also tcx for all non-netkit devices.
	// The underlying kernel does support it given tcx got merged
	// before netkit and supporting legacy tc in this context does
	// not make any sense whatsoever.
	if cc.operationalMode.IsNetkit() {
		p.DaemonConfig.EnableTCX = true
	}

	p.Log.Info("Datapath connector ready", logfields.DatapathMode, cc.operationalMode)

	return cc, nil
}

// calculateTunedBufferMargins aims to calculate necessary tuning parameters for pod/workload-facing
// network device pairs.
func (cc *ConnectorConfig) calculateTunedBufferMargins() error {
	if !cc.useTunedBufferMargins() {
		return nil
	}

	wgHeadroom, wgTailroom, err := cc.wgAgent.IfaceBufferMargins()
	if err != nil {
		return err
	}

	tunnelHeadroom, tunnelTailroom, err := cc.tunnelConfig.DeviceBufferMargins()
	if err != nil {
		return err
	}

	// There's nothing technically stopping these discovered values from being
	// to be on the high end of the underlying storage type. When combined, they
	// may overflow a U16.
	var totalHeadroom = uint32(wgHeadroom) + uint32(tunnelHeadroom)
	if totalHeadroom > math.MaxUint16 {
		cc.log.Warn("Total calculated headroom would exceed maximum value, using default",
			logfields.DeviceHeadroom, totalHeadroom)
	} else {
		cc.podDeviceHeadroom = uint16(totalHeadroom)
	}
	var totalTailroom = uint32(wgTailroom) + uint32(tunnelTailroom)
	if totalTailroom > math.MaxUint16 {
		cc.log.Warn("Total calculated tailroom would exceed maximum value, using default",
			logfields.DeviceTailroom, totalTailroom)
	} else {
		cc.podDeviceTailroom = uint16(totalTailroom)
	}
	return nil
}
