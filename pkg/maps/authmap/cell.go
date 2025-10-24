// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package authmap

import (
	"github.com/cilium/hive/cell"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/ebpf"
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

	cell.Provide(newAuthMap),
)

func newAuthMap(lifecycle cell.Lifecycle, config *option.DaemonConfig, mapSpecReg *registry.MapSpecRegistry) (bpf.MapOut[Map], error) {
	err := mapSpecReg.ModifyMapSpec(MapName, func(spec *ebpf.MapSpec) error {
		spec.MaxEntries = uint32(config.AuthMapEntries)
		return nil
	})
	if err != nil {
		return bpf.MapOut[Map]{}, err
	}

	m := &authMap{
		specReg: mapSpecReg,
	}
	lifecycle.Append(m)

	return bpf.NewMapOut(Map(m)), nil
}
