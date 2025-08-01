// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package types

import (
	"github.com/cilium/cilium/api/v1/models"

	wgTypes "github.com/cilium/cilium/pkg/wireguard/types"
)

var (
	_ wgTypes.WireguardAgent  = (*WireguardAgent)(nil)
	_ wgTypes.WireguardConfig = (*WireguardConfig)(nil)
)

type WireguardAgent struct {
	config WireguardConfig
}

func (fwa *WireguardAgent) Enabled() bool {
	return fwa.config.Enabled()
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
