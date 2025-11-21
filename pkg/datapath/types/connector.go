// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package types

import "github.com/cilium/cilium/pkg/datapath/option"

type ConnectorMode string

const (
	ConnectorModeUnspec   = ConnectorMode("")
	ConnectorModeVeth     = ConnectorMode(option.DatapathModeVeth)
	ConnectorModeNetkit   = ConnectorMode(option.DatapathModeNetkit)
	ConnectorModeNetkitL2 = ConnectorMode(option.DatapathModeNetkitL2)
)

func (mode ConnectorMode) IsLayer2() bool {
	switch mode {
	case ConnectorModeVeth, ConnectorModeNetkitL2:
		return true
	default:
		return false
	}
}

func (mode ConnectorMode) IsNetkit() bool {
	switch mode {
	case ConnectorModeNetkit, ConnectorModeNetkitL2:
		return true
	default:
		return false
	}
}

func (mode ConnectorMode) IsVeth() bool {
	return mode == ConnectorModeVeth
}

func (mode ConnectorMode) String() string {
	switch mode {
	case ConnectorModeVeth:
		return option.DatapathModeVeth
	case ConnectorModeNetkit:
		return option.DatapathModeNetkit
	case ConnectorModeNetkitL2:
		return option.DatapathModeNetkitL2
	default:
		return ""
	}
}

func GetConnectorModeByName(mode string) ConnectorMode {
	switch mode {
	case option.DatapathModeVeth:
		return ConnectorModeVeth
	case option.DatapathModeNetkit:
		return ConnectorModeNetkit
	case option.DatapathModeNetkitL2:
		return ConnectorModeNetkitL2
	default:
		return ConnectorModeUnspec
	}
}

type ConnectorConfig interface {
	Reinitialize() error
	GetPodDeviceHeadroom() uint16
	GetPodDeviceTailroom() uint16
	GetConfiguredMode() ConnectorMode
	GetOperationalMode() ConnectorMode
}
