// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package authmap

import (
	"fmt"

	"github.com/cilium/hive/cell"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/maps/registry"
	"github.com/cilium/cilium/pkg/option"
)

// Cell provides the auth.Map which contains the authentication state between Cilium security identities.
// Datapath checks the map for a valid authentication entry whenever authentication is demanded by a policy.
// If no or an expired entry is found the packet gets dropped and an authentication gets requested via
// auth.Manager.
var Cell = cell.Module(
	"auth-map",
	"eBPF map which manages authenticated connections between identities",

	cell.Provide(provide),
)

// provide an authMap to the Hive and configure its MapSpec in reg.
func provide(lc cell.Lifecycle, config *option.DaemonConfig, reg *registry.MapRegistry) (bpf.MapOut[Map], error) {
	if err := reg.Modify(MapName, func(m *registry.MapSpecPatch) {
		m.MaxEntries = uint32(config.AuthMapEntries)
	}); err != nil {
		return bpf.MapOut[Map]{}, fmt.Errorf("modify map spec: %w", err)
	}

	authMap := &authMap{}
	lc.Append(cell.Hook{
		OnStart: func(cell.HookContext) (err error) {
			authMap.m, err = bpf.NewMapFromRegistry(reg, MapName, &AuthKey{}, &AuthInfo{})
			if err != nil {
				return fmt.Errorf("create auth map: %w", err)
			}

			return authMap.m.OpenOrCreate()
		},
		OnStop: func(cell.HookContext) error {
			return authMap.m.Close()
		},
	})

	return bpf.NewMapOut(Map(authMap)), nil
}
