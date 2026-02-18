// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package node

import (
	"net"

	"github.com/cilium/cilium/pkg/datapath/tunnel"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/option"
	wgTypes "github.com/cilium/cilium/pkg/wireguard/types"
)

var addrs addresses

type addresses struct {
	mu         lock.RWMutex
	routerInfo RouterInfo
}

type RouterInfo interface {
	GetCIDRs() []net.IPNet
}

// GetCiliumEndpointNodeIP is the node IP that will be referenced by CiliumEndpoints with endpoints
// running on this node.
func GetCiliumEndpointNodeIP(localNode LocalNode) string {
	if option.Config.EnableIPv4 && localNode.Local.UnderlayProtocol == tunnel.IPv4 {
		return localNode.GetNodeIP(false).String()
	}
	return localNode.GetNodeIP(true).String()
}

// GetRouterInfo returns additional information for the router, the cilium_host interface.
func GetRouterInfo() RouterInfo {
	addrs.mu.RLock()
	defer addrs.mu.RUnlock()
	return addrs.routerInfo
}

// SetRouterInfo sets additional information for the router, the cilium_host interface.
func SetRouterInfo(info RouterInfo) {
	addrs.mu.Lock()
	addrs.routerInfo = info
	addrs.mu.Unlock()
}

// GetEndpointEncryptKeyIndex returns the encryption key value for an endpoint
// owned by the given local node.
// With IPSec encryption, this is the ID of the currently loaded key.
// With WireGuard, this returns a non-zero static value.
// Note that the key index returned by this function is only valid for _endpoints_
// of the local node. If you want to obtain the key index of the local node itself,
// access the `EncryptionKey` field via the LocalNodeStore.
func GetEndpointEncryptKeyIndex(localNode LocalNode, wgEnabled, ipsecEnabled bool) uint8 {
	switch {
	case ipsecEnabled:
		return localNode.EncryptionKey
	case wgEnabled:
		return wgTypes.StaticEncryptKey

	}
	return 0
}
