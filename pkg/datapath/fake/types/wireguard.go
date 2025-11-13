// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package types

import (
	"github.com/cilium/cilium/api/v1/models"

	"github.com/cilium/cilium/pkg/datapath/link"
	wgTypes "github.com/cilium/cilium/pkg/wireguard/types"
)

var (
	_ wgTypes.WireguardAgent  = (*WireguardAgent)(nil)
	_ wgTypes.WireguardConfig = (*WireguardConfig)(nil)
)

type WireguardAgent struct {
	config WireguardConfig
}

func NewTestAgent(fwc WireguardConfig) *WireguardAgent {
	wgAgent := &WireguardAgent{
		config: fwc,
	}
	return wgAgent
}

func (fwa *WireguardAgent) Enabled() bool {
	return fwa.config.Enabled()
}

// Fake IfaceIndex will still query the underlying system for the
// wireguard device. This will fail if not setup by the caller.
func (fwa *WireguardAgent) IfaceIndex() (uint32, error) {
	if !fwa.Enabled() {
		return 0, nil
	}
	return link.GetIfIndex(wgTypes.IfaceName)
}

// Fake IfaceBufferMargins will still query the underlying system for the
// wireguard device. This will fail if not setup by the caller.
func (fwa *WireguardAgent) IfaceBufferMargins() (uint16, uint16, error) {
	if !fwa.Enabled() {
		return 0, 0, nil
	}
	return link.GetIfBufferMargins(wgTypes.IfaceName)
}

func (fwa *WireguardAgent) Status(withPeers bool) (*models.WireguardStatus, error) {
	return nil, nil
}

type WireguardConfig struct {
	EnableWireguard bool
}

func (fwc WireguardConfig) Enabled() bool {
	return fwc.EnableWireguard
}
