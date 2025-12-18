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
		Constants: config.NewBPFNetwork(config.NodeConfig(lnc)),
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
