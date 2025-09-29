// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package connector

import (
	"github.com/cilium/hive/cell"

	"github.com/cilium/cilium/pkg/datapath/types"
)

// Default configuration
var defaultUserConfig = types.ConnectorUserConfig{
	EnableTunedBufferMargins: false,
}

var Cell = cell.Module(
	"connector",
	"Datapath connector configuration mutator",

	cell.Config(defaultUserConfig),
	cell.Provide(newConnectorConfig, func(c types.ConnectorUserConfig) types.ConnectorConfig { return c }),
	cell.Invoke(func(*ConnectorConfig) {}),
)
