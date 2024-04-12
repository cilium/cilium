// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package types

import (
	"net"

	"github.com/cilium/cilium/api/v1/models"
)

// WireguardAgent manages the WireGuard peers
type WireguardAgent interface {
	UpdatePeer(nodeName, pubKeyHex string, peerAddresses struct {
		NodeIPv4, NodeIPv6, ExternalIPv4, ExternalIPv6 net.IP
		UseExternalEndpoint                            bool
	}) error
	DeletePeer(nodeName string) error
	Status(includePeers bool) (*models.WireguardStatus, error)
}
