// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package connector

import (
	"github.com/cilium/hive/cell"
)

var Cell = cell.Module(
	"connector",
	"Datapath connector configuration mutator",

	cell.Provide(newConnectorConfig),
)

func newConnectorConfig(p connectorParams) (Config, error) {
	return newConfig(p)
}
