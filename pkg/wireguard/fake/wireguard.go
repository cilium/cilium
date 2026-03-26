// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package fake

import (
	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/datapath/link"
	"github.com/cilium/cilium/pkg/wireguard/types"
)

var (
	_ types.Agent  = (*Agent)(nil)
	_ types.Config = (*Config)(nil)
)

type Agent struct {
	config Config
}

func NewTestAgent(fwc Config) *Agent {
	wgAgent := &Agent{
		config: fwc,
	}
	return wgAgent
}

func (fwa *Agent) Enabled() bool {
	return fwa.config.Enabled()
}

// Fake IfaceIndex will still query the underlying system for the
// wireguard device. This will fail if not setup by the caller.
func (fwa *Agent) IfaceIndex() (uint32, error) {
	if !fwa.Enabled() {
		return 0, nil
	}
	return link.GetIfIndex(types.IfaceName)
}

// Fake IfaceBufferMargins will still query the underlying system for the
// wireguard device. This will fail if not setup by the caller.
func (fwa *Agent) IfaceBufferMargins() (uint16, uint16, error) {
	if !fwa.Enabled() {
		return 0, 0, nil
	}
	return link.GetIfBufferMargins(types.IfaceName)
}

func (fwa *Agent) Status(withPeers bool) (*models.WireguardStatus, error) {
	return nil, nil
}

type Config struct {
	EnableWireguard bool
}

func (fwc Config) Enabled() bool {
	return fwc.EnableWireguard
}
