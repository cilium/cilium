// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package defaultdns

import "github.com/cilium/hive/cell"

// Cell provides the DefaultDNSProxy for the entire process.
var Cell = cell.Module(
	"default-dns-proxy",
	"Provides the DefaultDNSProxy for the entire process",

	cell.Provide(NewProxy),
)
