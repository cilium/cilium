// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package types

import (
	"net"

	"github.com/cilium/cilium/api/v1/models"
)

// WireguardAgent manages the WireGuard peers
type WireguardAgent interface {
	UpdatePeer(nodeName, pubKeyHex string, nodeIPv4, nodeIPv6 net.IP) error
	DeletePeer(nodeName string) error
	Status(includePeers bool) (*models.WireguardStatus, error)
}
