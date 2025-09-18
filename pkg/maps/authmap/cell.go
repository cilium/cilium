// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package authmap

import (
	"log/slog"

	"github.com/cilium/hive/cell"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/option"
)

// Cell provides the auth.Map which contains the authentication state between Cilium security identities.
// Datapath checks the map for a valid authentication entry whenever authentication is demanded by a policy.
// If no or an expired entry is found the packet gets dropped and an authentication gets requested via
// auth.Manager.
var Cell = cell.Module(
	"auth-map",
	"eBPF map which manages authenticated connections between identities",

	cell.Provide(newAuthMap),
)

func newAuthMap(lifecycle cell.Lifecycle, logger *slog.Logger) bpf.MapOut[Map] {
	authMap := newMap(logger, option.Config.AuthMapEntries)

	lifecycle.Append(cell.Hook{
		OnStart: func(context cell.HookContext) error {
			return authMap.init()
		},
		OnStop: func(context cell.HookContext) error {
			return authMap.close()
		},
	})

	return bpf.NewMapOut(Map(authMap))
}
