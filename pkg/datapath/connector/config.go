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
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/option"
	wgTypes "github.com/cilium/cilium/pkg/wireguard/types"
)

type Config interface {
	Reinitialize() error
	GetPodDeviceHeadroom() uint16
	GetPodDeviceTailroom() uint16
	GetConfiguredMode() Mode
	GetOperationalMode() Mode
	NewLinkPair(cfg LinkConfig, sysctl sysctl.Sysctl) (LinkPair, error)
	GetLinkCompatibility(ifName string) (Mode, bool, error)
}

// Connector configuration. As per BIGTCP, the values here will not be calculated
// until the Hive has started. This is necessary to allow other dependencies to
// setup their interfaces etc.
type config struct {
	log          *slog.Logger
	wgAgent      wgTypes.Agent
	tunnelConfig tunnel.Config

	// podDeviceHeadroom tracks the desired headroom buffer margin for the
	// network device pair facing a workload.
	podDeviceHeadroom uint16

	// podDeviceTailroom tracks the desired tailroom buffer margin for the
	// network device pairs facing a workload.
	podDeviceTailroom uint16

	// configuredMode tracks the configured datapath mode of Cilium,
	// as specified by runtime configuration.
	configuredMode Mode

	// operationalMode tracks the operational datapath mode of Cilium,
	// which may differ from the configured datapath mode.
	operationalMode Mode
}

func (cc *config) Reinitialize() error {
	return cc.calculateTunedBufferMargins()
}

func (cc *config) GetPodDeviceHeadroom() uint16 {
	return cc.podDeviceHeadroom
}

func (cc *config) GetPodDeviceTailroom() uint16 {
	return cc.podDeviceTailroom
}

func (cc *config) GetConfiguredMode() Mode {
	return cc.configuredMode
}

func (cc *config) GetOperationalMode() Mode {
	return cc.operationalMode
}

func (cc *config) NewLinkPair(cfg LinkConfig, sysctl sysctl.Sysctl) (LinkPair, error) {
	return NewLinkPair(cc.log, cc.operationalMode, cfg, sysctl)
}

func (cc *config) GetLinkCompatibility(ifName string) (Mode, bool, error) {
	link, err := safenetlink.LinkByName(ifName)
	if err != nil {
		return ModeUnspec, false, err
	}

	linkMode := ModeByName(link.Type())

	// The netkit driver supports both L2 and L3 modes, which we can't identify
	// by the link type. If the link is operating at L2 mode, the above getter
	// will return the L3 type. Probe the netkit structure to fix this up.
	if linkMode == ModeNetkit {
		nk := link.(*netlink.Netkit)
		if nk.Mode == netlink.NETKIT_MODE_L2 {
			linkMode = ModeNetkitL2
		}
	}

	linkCompatible := cc.operationalMode == linkMode

	return linkMode, linkCompatible, nil
}

// Returns true if we should actively try and align the connector's netdev buffer
// margins with that of the host's egress interfaces (e.g. tunnel, wireguard).
func (cc *config) useTunedBufferMargins() bool {
	return cc.operationalMode.IsNetkit()
}

type connectorParams struct {
	cell.In

	Lifecycle    cell.Lifecycle
	Log          *slog.Logger
	DaemonConfig *option.DaemonConfig
	WgAgent      wgTypes.Agent
	TunnelConfig tunnel.Config
}

func canUseNetkit(p connectorParams) error {
	if err := probes.HaveNetkit(); err != nil {
		return fmt.Errorf("netkit device probe failed, requires kernel 6.7.0+ and CONFIG_NETKIT")
	}

	// We should only run netkit with BPF Host Routing.
	if p.DaemonConfig.UnsafeDaemonConfigOption.EnableHostLegacyRouting {
		return fmt.Errorf("netkit devices cannot be used with --%s=true", option.EnableHostLegacyRouting)
	}

	// early versions of netkit would scrub skb metadata before execution of BPF
	// programs, meaning identity data stored in skb metadata would not be available
	// to BPF programs. When using per-endpoint-routes, this can result in network
	// policy mis-classification.
	//
	// A fix in the netkit driver landed in kernel 6.13 [0]. This fix was backported
	// to stable branches. Cilium was also updated to configure netkit devices with
	// an appropriate scrubbing attribute [1].
	//
	// [0] https://lore.kernel.org/bpf/20241004101335.117711-1-daniel@iogearbox.net
	// [1] https://github.com/cilium/cilium/pull/35306
	//
	// To avoid issues, if we're running with per-endpoint-routes, we probe the host
	// for scrub attribute support and raise errors if it's missing.
	if p.DaemonConfig.EnableEndpointRoutes {
		if err := probes.HaveNetkitScrub(); err != nil {
			return fmt.Errorf("netkit driver missing scrub attributes, required with --%s=true",
				option.EnableEndpointRoutes)
		}
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
func newConfig(p connectorParams) (*config, error) {
	var configuredMode, operationalMode Mode

	configuredMode = ModeByName(p.DaemonConfig.DatapathMode)
	switch configuredMode {
	case ModeUnspec:
		return nil, fmt.Errorf("invalid datapath mode: %s", p.DaemonConfig.DatapathMode)

	case ModeAuto:
		if err := canUseNetkit(p); err != nil {
			p.Log.Warn("datapath autodiscovery failed, reverting from netkit to veth",
				logfields.Error, err)
			operationalMode = ModeVeth
		} else {
			operationalMode = ModeNetkit
		}

	case ModeNetkit, ModeNetkitL2:
		if err := canUseNetkit(p); err != nil {
			return nil, fmt.Errorf("netkit connector not available: %w", err)
		}

		fallthrough

	default:
		operationalMode = configuredMode
	}

	cc := &config{
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
func (cc *config) calculateTunedBufferMargins() error {
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
