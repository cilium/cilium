// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package types

import (
	"github.com/vishvananda/netlink"

	"github.com/cilium/cilium/pkg/datapath/linux/sysctl"
	"github.com/cilium/cilium/pkg/datapath/types"
)

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
func NewFakeConnectorAutoVeth(operationalMode types.ConnectorMode) types.ConnectorConfig {
	return NewFakeConnectorConfig(types.ConnectorModeAuto, types.ConnectorModeVeth)
}
func NewFakeConnectorAutoNetkit(operationalMode types.ConnectorMode) types.ConnectorConfig {
	return NewFakeConnectorConfig(types.ConnectorModeAuto, types.ConnectorModeNetkit)
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

func (fcc fakeConnectorConfig) NewLinkPair(cfg types.LinkConfig, sysctl sysctl.Sysctl) (types.LinkPair, error) {
	return &fakeLinkPair{mode: fcc.operationalMode}, nil
}

func (fcc fakeConnectorConfig) GetLinkCompatibility(ifName string) (types.ConnectorMode, bool, error) {
	return types.ConnectorModeUnspec, false, nil
}

type fakeLinkPair struct {
	mode types.ConnectorMode
}

func (flp fakeLinkPair) GetHostLink() netlink.Link {
	return nil
}

func (flp fakeLinkPair) GetPeerLink() netlink.Link {
	return nil
}

func (flp fakeLinkPair) GetMode() types.ConnectorMode {
	return flp.mode
}

func (flp fakeLinkPair) Delete() error {
	return nil
}
