// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package types

import "github.com/cilium/cilium/pkg/datapath/types"

type fakeConnectorConfig struct {
	configuredMode  types.ConnectorMode
	operationalMode types.ConnectorMode
}

func NewFakeConnectorConfig(configuredMode types.ConnectorMode, operationalMode types.ConnectorMode) types.ConnectorConfig {
	return &fakeConnectorConfig{
		configuredMode:  configuredMode,
		operationalMode: operationalMode,
	}
}
func NewFakeConnectorVeth() types.ConnectorConfig {
	return NewFakeConnectorConfig(types.ConnectorModeVeth, types.ConnectorModeVeth)
}
func NewFakeConnectorNetkit() types.ConnectorConfig {
	return NewFakeConnectorConfig(types.ConnectorModeNetkit, types.ConnectorModeNetkit)
}
func NewFakeConnectorNetkitL2() types.ConnectorConfig {
	return NewFakeConnectorConfig(types.ConnectorModeNetkitL2, types.ConnectorModeNetkitL2)
}

func (fcc fakeConnectorConfig) Reinitialize() error {
	return nil
}

func (fcc fakeConnectorConfig) GetPodDeviceHeadroom() uint16 {
	return 0
}

func (fcc fakeConnectorConfig) GetPodDeviceTailroom() uint16 {
	return 0
}

func (fcc fakeConnectorConfig) GetConfiguredMode() types.ConnectorMode {
	return fcc.configuredMode
}

func (fcc fakeConnectorConfig) GetOperationalMode() types.ConnectorMode {
	return fcc.operationalMode
}
