// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build ipam_provider_operator

package ipam

import (
	"log/slog"

	"github.com/cilium/hive/cell"

	"github.com/cilium/cilium/operator/pkg/ipam/allocator/multipool"
	ipamOption "github.com/cilium/cilium/pkg/ipam/option"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/option"
)

func init() {
	allocators = append(allocators, cell.Module(
		"multipool-ipam-allocator",
		"Multi Pool IP Allocator",

		cell.Config(multipool.DefaultConfig),
		cell.Decorate(
			func(logger *slog.Logger) *slog.Logger {
				return logger.With(logfields.LogSubsys, "ipam-allocator-multi-pool")
			},
			cell.ProvidePrivate(
				func(logger *slog.Logger, daemonCfg *option.DaemonConfig) *multipool.PoolAllocator {
					if daemonCfg.IPAM != ipamOption.IPAMMultiPool {
						return nil
					}

					return multipool.NewPoolAllocator(logger, daemonCfg.EnableIPv4, daemonCfg.EnableIPv6)
				},
			),
			cell.Invoke(multipool.StartAllocator),
		),
	))
}
