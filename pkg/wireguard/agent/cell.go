// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package agent

import (
	"github.com/cilium/hive/cell"

	"github.com/cilium/cilium/pkg/wireguard/types"
)

var Cell = cell.Module(
	"wireguard-agent",
	"Manages WireGuard device and peers",

	cell.Provide(newWireguardAgent),
)

// newWireguardAgent returns the [*Agent] as an interface [types.WireguardAgent].
func newWireguardAgent(p params) types.WireguardAgent {
	return newAgent(p)
}
