// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package types

import (
	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/datapath/types"
)

var _ types.WireguardAgent = (*WireguardAgent)(nil)

type WireguardAgent struct{}

func (fwa *WireguardAgent) Enabled() bool {
	return false
}

func (fwa *WireguardAgent) Status(withPeers bool) (*models.WireguardStatus, error) {
	return nil, nil
}
