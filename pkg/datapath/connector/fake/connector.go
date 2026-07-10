// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package fake

import (
	"github.com/vishvananda/netlink"

	"github.com/cilium/cilium/pkg/datapath/connector"
	"github.com/cilium/cilium/pkg/datapath/linux/sysctl"
)

type config struct {
	configuredMode  connector.Mode
	operationalMode connector.Mode
}

func NewConfig(configuredMode connector.Mode, operationalMode connector.Mode) connector.Config {
	return &config{
		configuredMode:  configuredMode,
		operationalMode: operationalMode,
	}
}
func NewAutoVeth(operationalMode connector.Mode) connector.Config {
	return NewConfig(connector.ModeAuto, connector.ModeVeth)
}
func NewAutoNetkit(operationalMode connector.Mode) connector.Config {
	return NewConfig(connector.ModeAuto, connector.ModeNetkit)
}
func NewVeth() connector.Config {
	return NewConfig(connector.ModeVeth, connector.ModeVeth)
}
func NewNetkit() connector.Config {
	return NewConfig(connector.ModeNetkit, connector.ModeNetkit)
}
func NewNetkitL2() connector.Config {
	return NewConfig(connector.ModeNetkitL2, connector.ModeNetkitL2)
}

func (fcc config) Reinitialize() error {
	return nil
}

func (fcc config) GetPodDeviceHeadroom() uint16 {
	return 0
}

func (fcc config) GetPodDeviceTailroom() uint16 {
	return 0
}

func (fcc config) GetConfiguredMode() connector.Mode {
	return fcc.configuredMode
}

func (fcc config) GetOperationalMode() connector.Mode {
	return fcc.operationalMode
}

func (fcc config) NewLinkPair(cfg connector.LinkConfig, sysctl sysctl.Sysctl) (connector.LinkPair, error) {
	return &linkPair{mode: fcc.operationalMode}, nil
}

func (fcc config) GetLinkCompatibility(ifName string) (connector.Mode, bool, error) {
	return connector.ModeUnspec, false, nil
}

type linkPair struct {
	mode connector.Mode
}

func (flp linkPair) GetHostLink() netlink.Link {
	return nil
}

func (flp linkPair) GetPeerLink() netlink.Link {
	return nil
}

func (flp linkPair) GetMode() connector.Mode {
	return flp.mode
}

func (flp linkPair) Delete() error {
	return nil
}
