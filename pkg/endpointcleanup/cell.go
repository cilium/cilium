// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package endpointcleanup

import (
	"github.com/spf13/pflag"

	"github.com/cilium/cilium/pkg/endpointmanager"
	"github.com/cilium/cilium/pkg/hive/cell"
)

var Cell = cell.Module(
	"stale-endpoint-cleanup",
	"Cleanup stale cilium endpoints from unmanaged pods at startup",

	cell.Invoke(registerCleanup),
	cell.ProvidePrivate(func(epMgr endpointmanager.EndpointManager) localEndpointCache {
		return epMgr
	}),
	cell.Config(Config{}),
)

type Config struct {
	// EnableStaleCiliumEndpointCleanup enables cleanup routine during Cilium init.
	// This will attempt to remove local CiliumEndpoints that are not managed by Cilium
	// following Endpoint restoration.
	EnableStaleCiliumEndpointCleanup bool
}

func (def Config) Flags(flags *pflag.FlagSet) {
	flags.Bool("enable-stale-cilium-endpoint-cleanup", true, "Enable running cleanup init procedure of local CiliumEndpoints which are not being managed.")
	flags.MarkHidden("enable-stale-cilium-endpoint-cleanup")
}
