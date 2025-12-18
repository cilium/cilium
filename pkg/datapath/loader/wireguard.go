// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package loader

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/cilium/ebpf"
	"github.com/vishvananda/netlink"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/datapath/config"
	datapathOption "github.com/cilium/cilium/pkg/datapath/option"
	datapath "github.com/cilium/cilium/pkg/datapath/types"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/option"
)

const (
	symbolToWireguard   = "cil_to_wireguard"
	symbolFromWireguard = "cil_from_wireguard"
)

func replaceWireguardDatapath(ctx context.Context, logger *slog.Logger, lnc *datapath.LocalNodeConfiguration, device netlink.Link) (err error) {
	if err := compileWireguard(ctx, logger); err != nil {
		return fmt.Errorf("compiling wireguard program: %w", err)
	}

	spec, err := ebpf.LoadCollectionSpec(wireguardObj)
	if err != nil {
		return fmt.Errorf("loading eBPF ELF %s: %w", wireguardObj, err)
	}

	cfg := config.NewBPFWireguard(config.NodeConfig(lnc))
	cfg.InterfaceIfIndex = uint32(device.Attrs().Index)

	cfg.EnableExtendedIPProtocols = option.Config.EnableExtendedIPProtocols
	cfg.EnableNetkit = option.Config.DatapathMode == datapathOption.DatapathModeNetkit ||
		option.Config.DatapathMode == datapathOption.DatapathModeNetkitL2

	cfg.EphemeralMin = lnc.EphemeralMin

	var obj wireguardObjects
	commit, err := bpf.LoadAndAssign(logger, &obj, spec, &bpf.CollectionOptions{
		Constants: cfg,
		MapRenames: map[string]string{
			"cilium_calls": fmt.Sprintf("cilium_calls_wireguard_%d", device.Attrs().Index),
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
	// Attach/detach cil_to_wireguard to/from egress.
	if option.Config.NeedEgressOnWireGuardDevice(lnc.KPRConfig, lnc.EnableWireguard) {
		if err := attachSKBProgram(logger, device, obj.ToWireguard, symbolToWireguard,
			linkDir, netlink.HANDLE_MIN_EGRESS, option.Config.EnableTCX); err != nil {
			return fmt.Errorf("interface %s egress: %w", device, err)
		}
	} else {
		if err := detachSKBProgram(logger, device, symbolToWireguard,
			linkDir, netlink.HANDLE_MIN_EGRESS); err != nil {
			logger.Error("",
				logfields.Error, err,
				logfields.Device, device,
			)
		}
	}
	// Attach/detach cil_from_wireguard to/from ingress.
	if option.Config.NeedIngressOnWireGuardDevice(lnc.KPRConfig, lnc.EnableWireguard) {
		if err := attachSKBProgram(logger, device, obj.FromWireguard, symbolFromWireguard,
			linkDir, netlink.HANDLE_MIN_INGRESS, option.Config.EnableTCX); err != nil {
			return fmt.Errorf("interface %s ingress: %w", device, err)
		}
	} else {
		if err := detachSKBProgram(logger, device, symbolFromWireguard,
			linkDir, netlink.HANDLE_MIN_INGRESS); err != nil {
			logger.Error("",
				logfields.Error, err,
				logfields.Device, device,
			)
		}
	}
	if err := commit(); err != nil {
		return fmt.Errorf("committing bpf pins: %w", err)
	}
	return nil
}
