// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package mode

import (
	"github.com/cilium/cilium/pkg/lock"
)

// Mode defines the modes in which BGP agent can be configured.
type Mode int

const (
	// Disabled mode, BGP control plane is not enabled
	Disabled Mode = iota
	// BGPv1 mode is enabled, BGP configuration of the agent will rely on matching CiliumBGPPeeringPolicy for the node.
	BGPv1
	// BGPv2 mode is enabled, BGP configuration of the agent will rely on CiliumBGPNodeConfig, CiliumBGPAdvertisement and CiliumBGPPeerConfig.
	BGPv2
)

func NewConfigMode() *ConfigMode {
	return &ConfigMode{}
}

type ConfigMode struct {
	lock.RWMutex
	configMode Mode
}

func (m *ConfigMode) Get() Mode {
	m.RLock()
	defer m.RUnlock()
	return m.configMode
}

func (m *ConfigMode) Set(mode Mode) {
	m.Lock()
	defer m.Unlock()
	m.configMode = mode
}
