// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package agent

import (
	"context"
	"iter"
	"net/netip"

	"github.com/cilium/statedb"
	"github.com/cilium/statedb/reconciler"

	"github.com/cilium/cilium/pkg/node"
)

var _ reconciler.Operations[*node.Node] = (*Agent)(nil)

func (a *Agent) Update(
	_ context.Context,
	_ statedb.ReadTxn,
	_ statedb.Revision,
	n *node.Node,
) error {
	if n.Local != nil {
		return nil
	}
	if n.WireguardPubKey == "" {
		return a.deletePeer(n.Fullname())
	}
	return a.updatePeer(
		n.Fullname(),
		n.WireguardPubKey,
		n.GetNodeIP(false).AsSlice(),
		n.GetNodeIP(true).AsSlice(),
		nodeOwnedAllowedIPs(n)...,
	)
}

// nodeOwnedAllowedIPs returns the remote node's health, ingress, and pod
// allocation prefixes that must be present in the WireGuard peer AllowedIPs
// when running in native routing mode. These prefixes are published on the
// CiliumNode object and cover traffic that is otherwise missing from the
// IPCache-driven AllowedIPs path (see https://github.com/cilium/cilium/issues/44915).
func nodeOwnedAllowedIPs(n *node.Node) []netip.Prefix {
	if n == nil {
		return nil
	}

	prefixes := make([]netip.Prefix, 0, 4+len(n.GetIPv4AllocCIDRs())+len(n.GetIPv6AllocCIDRs()))
	for _, addr := range []netip.Addr{
		n.IPv4HealthIP.Addr,
		n.IPv6HealthIP.Addr,
		n.IPv4IngressIP.Addr,
		n.IPv6IngressIP.Addr,
	} {
		if !addr.IsValid() {
			continue
		}
		prefixes = append(prefixes, netip.PrefixFrom(addr, addr.BitLen()))
	}
	prefixes = append(prefixes, n.GetIPv4AllocCIDRs()...)
	prefixes = append(prefixes, n.GetIPv6AllocCIDRs()...)
	return prefixes
}

func (a *Agent) Delete(
	_ context.Context,
	_ statedb.ReadTxn,
	_ statedb.Revision,
	n *node.Node,
) error {
	if n.Local != nil {
		return nil
	}
	return a.deletePeer(n.Fullname())
}

// Pruning is handled by peerGarbageCollector after all node and IPCache
// sources have synchronized.
func (a *Agent) Prune(
	context.Context,
	statedb.ReadTxn,
	iter.Seq2[*node.Node, statedb.Revision],
) error {
	return nil
}
