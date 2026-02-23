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
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/option"
)

func init() {
	overlayConfigs.register(config.Overlay)
	overlayRenames.register(defaultOverlayMapRenames)
}

const (
	symbolFromOverlay = "cil_from_overlay"
	symbolToOverlay   = "cil_to_overlay"
)

// overlayConfigs holds functions that yield a BPF configuration object for
// an overlay (tunneling) network device.
var overlayConfigs funcRegistry[func(*datapath.LocalNodeConfiguration, netlink.Link) any]

// overlayConfigs holds functions that yield BPF map renames for an overlay (tunneling) network device.
var overlayRenames funcRegistry[func(*datapath.LocalNodeConfiguration, netlink.Link) map[string]string]

// overlayConfiguration returns a slice of BPF configuration objects yielded
// by all registered config providers of [overlayConfigs].
func overlayConfiguration(lnc *datapath.LocalNodeConfiguration, link netlink.Link) (configs []any) {
	for f := range overlayConfigs.all() {
		configs = append(configs, f(lnc, link))
	}
	return configs
}

// overlayMapRenames returns the merged map of overlay map renames yielded by all registered rename providers.
func overlayMapRenames(lnc *datapath.LocalNodeConfiguration, link netlink.Link) (renames []map[string]string) {
	for f := range overlayRenames.all() {
		renames = append(renames, f(lnc, link))
	}
	return renames
}

func defaultOverlayMapRenames(lnc *datapath.LocalNodeConfiguration, link netlink.Link) (renames map[string]string) {
	return map[string]string{
		"cilium_calls": fmt.Sprintf("cilium_calls_overlay_%d", identity.ReservedIdentityWorld),
	}
}

func replaceOverlayDatapath(ctx context.Context, logger *slog.Logger, lnc *datapath.LocalNodeConfiguration, link netlink.Link) error {
	if err := compileOverlay(ctx, logger); err != nil {
		return fmt.Errorf("compiling overlay program: %w", err)
	}

	spec, err := ebpf.LoadCollectionSpec(overlayObj)
	if err != nil {
		return fmt.Errorf("loading eBPF ELF %s: %w", overlayObj, err)
	}

	var obj overlayObjects
	commit, err := bpf.LoadAndAssign(logger, &obj, spec, &bpf.CollectionOptions{
		Constants:  overlayConfiguration(lnc, link),
		MapRenames: overlayMapRenames(lnc, link),
		CollectionOptions: ebpf.CollectionOptions{
			Maps: ebpf.MapOptions{PinPath: bpf.TCGlobalsPath()},
		},
		ConfigDumpPath: filepath.Join(bpfStateDeviceDir(link.Attrs().Name), overlayConfig),
	})
	if err != nil {
		return err
	}
	defer obj.Close()

	linkDir := bpffsDeviceLinksDir(bpf.CiliumPath(), link)
	if err := attachSKBProgram(logger, link, obj.FromOverlay, symbolFromOverlay,
		linkDir, netlink.HANDLE_MIN_INGRESS, option.Config.EnableTCX); err != nil {
		return fmt.Errorf("interface %s ingress: %w", link, err)
	}
	if err := attachSKBProgram(logger, link, obj.ToOverlay, symbolToOverlay,
		linkDir, netlink.HANDLE_MIN_EGRESS, option.Config.EnableTCX); err != nil {
		return fmt.Errorf("interface %s egress: %w", link, err)
	}

	if err := commit(); err != nil {
		return fmt.Errorf("committing bpf pins: %w", err)
	}

	return nil
}
