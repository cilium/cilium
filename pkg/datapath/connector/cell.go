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

// Connector configuration. As per BIGTCP, the values here will not be calculated
// until the Hive has started. This is necessary to allow other dependencies to
// setup their interfaces etc.
type ConnectorConfig struct {
	UserConfig types.ConnectorUserConfig

	// podDeviceHeadroom tracks the desired headroom buffer margin for the
	// network device pair facing a workload.
	podDeviceHeadroom uint16

	// podDeviceTailroom tracks the desired tailroom buffer margin for the
	// network device pairs facing a workload.
	podDeviceTailroom uint16
}

func (cc *ConnectorConfig) GetPodDeviceHeadroom() uint16 {
	return cc.podDeviceHeadroom
}

func (cc *ConnectorConfig) GetPodDeviceTailroom() uint16 {
	return cc.podDeviceTailroom
}
