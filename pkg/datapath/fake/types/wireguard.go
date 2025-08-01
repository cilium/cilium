// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package types

import (
	"github.com/cilium/cilium/api/v1/models"

	wgTypes "github.com/cilium/cilium/pkg/wireguard/types"
)

var (
	_ wgTypes.WireguardAgent = (*WireguardAgent)(nil)
)

type WireguardAgent struct {
	EnableWireguard bool
}

func (fwa *WireguardAgent) Enabled() bool {
	return fwa.EnableWireguard
}

func (fwa *WireguardAgent) Status(withPeers bool) (*models.WireguardStatus, error) {
	return nil, nil
}
