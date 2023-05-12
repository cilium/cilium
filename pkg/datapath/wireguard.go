// SPDX-License-Identifier: Apache-2.0
// Copyright 2021 Authors of Cilium

package datapath

import (
	"net"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/mtu"
)

// WireguardAgent manages the Wireguard peers
type WireguardAgent interface {
	NodeHandler
	Init(mtuConfig mtu.Configuration) error
	UpdatePeer(nodeName, pubKeyHex string, nodeIPv4, nodeIPv6 net.IP) error
	DeletePeer(nodeName string) error
	Status(includePeers bool) (*models.WireguardStatus, error)
}
