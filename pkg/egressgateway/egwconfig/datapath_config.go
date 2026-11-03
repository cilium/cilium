// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package egwconfig

import "github.com/cilium/hive/cell"

var Cell = cell.Group(
	cell.Provide(newDatapathConfig),
)

type Config struct {
	enabledEgressGateway       bool
	enabledEgressGatewayCommon bool
}

func newDatapathConfig() *Config {
	return &Config{}
}

func (dc *Config) IsEgressGatewayEnabled() bool {
	if dc == nil {
		return false
	}

	return dc.enabledEgressGateway
}

func (dc *Config) EnableEgressGateway() {
	dc.enabledEgressGateway = true
	dc.enabledEgressGatewayCommon = true
}

func (dc *Config) IsEgressGatewayCommonEnabled() bool {
	if dc == nil {
		return false
	}

	return dc.enabledEgressGatewayCommon
}

func (dc *Config) EnableEgressGatewayCommon() {
	dc.enabledEgressGatewayCommon = true
}

func (dc *Config) DeepEqual(other *Config) bool {
	if dc == nil && other == nil {
		return true
	}
	if dc == nil || other == nil {
		return false
	}
	return dc.enabledEgressGateway == other.enabledEgressGateway &&
		dc.enabledEgressGatewayCommon == other.enabledEgressGatewayCommon
}
