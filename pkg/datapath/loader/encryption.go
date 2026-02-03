// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package loader

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"github.com/cilium/ebpf"
	"github.com/vishvananda/netlink"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/datapath/config"
	datapath "github.com/cilium/cilium/pkg/datapath/types"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/option"
)

func init() {
	encryptionConfigs.register(config.Encryption)
}

// encryptionConfigs holds functions that yield a BPF configuration object for
// attaching instances of bpf_network.c to externally-facing network devices.
var encryptionConfigs funcRegistry[func(*datapath.LocalNodeConfiguration) any]

// encryptionRenames holds functions that yield BPF map renames for
// attaching instances of bpf_network.c to externally-facing network devices.
var encryptionRenames funcRegistry[func(*datapath.LocalNodeConfiguration) map[string]string]

// encryptionConfiguration returns a slice of BPF configuration objects yielded
// by all registered config providers of [encryptionConfigs].
func encryptionConfiguration(lnc *datapath.LocalNodeConfiguration) (configs []any) {
	for f := range encryptionConfigs.all() {
		configs = append(configs, f(lnc))
	}
	return configs
}

// encryptionMapRenames returns the merged map of encryption map renames yielded by all registered rename providers.
func encryptionMapRenames(lnc *datapath.LocalNodeConfiguration) (renames []map[string]string) {
	for f := range encryptionRenames.all() {
		renames = append(renames, f(lnc))
	}
	return renames
}

func replaceEncryptionDatapath(ctx context.Context, logger *slog.Logger, lnc *datapath.LocalNodeConfiguration, links []netlink.Link) error {
	if err := compileNetwork(ctx, logger); err != nil {
		return fmt.Errorf("compiling encrypt program: %w", err)
	}

	spec, err := ebpf.LoadCollectionSpec(networkObj)
	if err != nil {
		return fmt.Errorf("loading eBPF ELF %s: %w", networkObj, err)
	}

	var obj networkObjects
	commit, err := bpf.LoadAndAssign(logger, &obj, spec, &bpf.CollectionOptions{
		CollectionOptions: ebpf.CollectionOptions{
			Maps: ebpf.MapOptions{PinPath: bpf.TCGlobalsPath()},
		},
		Constants:  encryptionConfiguration(lnc),
		MapRenames: encryptionMapRenames(lnc),
		// A single bpf_network.o Collection is attached to multiple devices, only
		// store a single config at the root of the bpf statedir.
		ConfigDumpPath: bpfStateDeviceDir(networkConfig),
	})
	if err != nil {
		return err
	}
	defer obj.Close()

	var errs error
	for _, link := range links {
		if err := attachSKBProgram(logger, link, obj.FromNetwork, symbolFromNetwork,
			bpffsDeviceLinksDir(bpf.CiliumPath(), link), netlink.HANDLE_MIN_INGRESS, option.Config.EnableTCX); err != nil {

			// Collect errors, keep attaching to other interfaces.
			errs = errors.Join(errs, fmt.Errorf("interface %s: %w", link.Attrs().Name, err))
			continue
		}

		logger.Info("Encryption network program (re)loaded", logfields.Interface, link.Attrs().Name)
	}

	if errs != nil {
		return fmt.Errorf("failed to load encryption program: %w", errs)
	}

	if err := commit(); err != nil {
		return fmt.Errorf("committing bpf pins: %w", err)
	}

	return nil
}
