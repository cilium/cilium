// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package loader

import (
	"context"
	"fmt"
	"log/slog"
	"path/filepath"

	"github.com/cilium/ebpf"
	"github.com/vishvananda/netlink"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/datapath/config"
	datapath "github.com/cilium/cilium/pkg/datapath/types"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/option"
)

func init() {
	wireguardConfigs.register(config.Wireguard)
}

const (
	symbolToWireguard   = "cil_to_wireguard"
	symbolFromWireguard = "cil_from_wireguard"
)

// wireguardConfigs holds functions that yield a BPF configuration object for
// the wireguard network device.
var wireguardConfigs funcRegistry[func(*datapath.LocalNodeConfiguration, netlink.Link) any]

// wireguardConfiguration returns a slice of BPF configuration objects yielded
// by all registered config providers of [wireguardConfigs].
func wireguardConfiguration(lnc *datapath.LocalNodeConfiguration, link netlink.Link) (configs []any) {
	for f := range wireguardConfigs.all() {
		configs = append(configs, f(lnc, link))
	}
	return configs
}

func replaceWireguardDatapath(ctx context.Context, logger *slog.Logger, lnc *datapath.LocalNodeConfiguration, device netlink.Link) (err error) {
	if err := compileWireguard(ctx, logger); err != nil {
		return fmt.Errorf("compiling wireguard program: %w", err)
	}

	spec, err := ebpf.LoadCollectionSpec(wireguardObj)
	if err != nil {
		return fmt.Errorf("loading eBPF ELF %s: %w", wireguardObj, err)
	}

	var obj wireguardObjects
	commit, err := bpf.LoadAndAssign(logger, &obj, spec, &bpf.CollectionOptions{
		Constants: wireguardConfiguration(lnc, device),
		MapRenames: map[string]string{
			"cilium_calls": fmt.Sprintf("cilium_calls_wireguard_%d", device.Attrs().Index),
		},
		CollectionOptions: ebpf.CollectionOptions{
			Maps: ebpf.MapOptions{PinPath: bpf.TCGlobalsPath()},
		},
		ConfigDumpPath: filepath.Join(bpfStateDeviceDir(device.Attrs().Name), wireguardConfig),
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
	// Attach cil_from_wireguard to ingress unconditionally,
	// making sure from_wireguard always marks decrypted wireguard traffic.
	if err := attachSKBProgram(logger, device, obj.FromWireguard, symbolFromWireguard,
		linkDir, netlink.HANDLE_MIN_INGRESS, option.Config.EnableTCX); err != nil {
		return fmt.Errorf("interface %s ingress: %w", device, err)
	}
	if err := commit(); err != nil {
		return fmt.Errorf("committing bpf pins: %w", err)
	}
	return nil
}
