// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package loader

import (
	"context"
	"fmt"
	"log/slog"
	"net"

	"github.com/cilium/ebpf"
	"github.com/vishvananda/netlink"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/byteorder"
	"github.com/cilium/cilium/pkg/datapath/config"
	datapathOption "github.com/cilium/cilium/pkg/datapath/option"
	datapath "github.com/cilium/cilium/pkg/datapath/types"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/option"
)

const (
	symbolFromOverlay = "cil_from_overlay"
	symbolToOverlay   = "cil_to_overlay"
)

func replaceOverlayDatapath(ctx context.Context, logger *slog.Logger, lnc *datapath.LocalNodeConfiguration, device netlink.Link) error {
	if err := compileOverlay(ctx, logger); err != nil {
		return fmt.Errorf("compiling overlay program: %w", err)
	}

	spec, err := ebpf.LoadCollectionSpec(overlayObj)
	if err != nil {
		return fmt.Errorf("loading eBPF ELF %s: %w", overlayObj, err)
	}

	cfg := config.NewBPFOverlay(config.NodeConfig(lnc))
	cfg.InterfaceIfIndex = uint32(device.Attrs().Index)

	cfg.EnableExtendedIPProtocols = option.Config.EnableExtendedIPProtocols
	cfg.EnableNoServiceEndpointsRoutable = lnc.SvcRouteConfig.EnableNoServiceEndpointsRoutable
	cfg.EnableNetkit = option.Config.DatapathMode == datapathOption.DatapathModeNetkit ||
		option.Config.DatapathMode == datapathOption.DatapathModeNetkitL2

	if option.Config.EnableVTEP {
		cfg.VTEPMask = byteorder.NetIPv4ToHost32(net.IP(option.Config.VtepCidrMask))
	}

	cfg.EphemeralMin = lnc.EphemeralMin

	var obj overlayObjects
	commit, err := bpf.LoadAndAssign(logger, &obj, spec, &bpf.CollectionOptions{
		Constants: cfg,
		MapRenames: map[string]string{
			"cilium_calls": fmt.Sprintf("cilium_calls_overlay_%d", identity.ReservedIdentityWorld),
		},
		CollectionOptions: ebpf.CollectionOptions{
			Maps: ebpf.MapOptions{PinPath: bpf.TCGlobalsPath()},
		},
	})
	if err != nil {
		return err
	}
	defer obj.Close()

	linkDir := bpffsDeviceLinksDir(bpf.CiliumPath(), device)
	if err := attachSKBProgram(logger, device, obj.FromOverlay, symbolFromOverlay,
		linkDir, netlink.HANDLE_MIN_INGRESS, option.Config.EnableTCX); err != nil {
		return fmt.Errorf("interface %s ingress: %w", device, err)
	}
	if err := attachSKBProgram(logger, device, obj.ToOverlay, symbolToOverlay,
		linkDir, netlink.HANDLE_MIN_EGRESS, option.Config.EnableTCX); err != nil {
		return fmt.Errorf("interface %s egress: %w", device, err)
	}

	if err := commit(); err != nil {
		return fmt.Errorf("committing bpf pins: %w", err)
	}

	return nil
}
