// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package healthcheck

import (
	"context"
	"fmt"

	"github.com/cilium/cilium/pkg/bgpv1/agent"
	"github.com/cilium/cilium/pkg/bgpv1/types"
)

type BgpStatusGetter interface {
	GetBGPPeerStatus(ctx context.Context) (bool, string)
	GetBGPPeerStatusWithMode(ctx context.Context, mode string, requireBGP bool) (bool, string)
}

func NewBGPStatusGetter(routerManager agent.BGPRouterManager, cfg Config) BgpStatusGetter {
	return &healthchecker{
		RouterManager: routerManager,
		config:        cfg,
	}
}

type healthchecker struct {
	RouterManager agent.BGPRouterManager
	config        Config
}

func (h *healthchecker) GetBGPPeerStatus(ctx context.Context) (bool, string) {
	return h.GetBGPPeerStatusWithMode(ctx, h.config.BGPReadinessMode, h.config.BGPReadinessEnabled)
}

func (h *healthchecker) GetBGPPeerStatusWithMode(ctx context.Context, mode string, requireBGP bool) (bool, string) {
	if !requireBGP {
		return true, "BGP health check is not required"
	}

	// Validate that RouterManager is available
	if h.RouterManager == nil {
		return false, "Error: BGP router manager not available"
	}

	peers, err := h.RouterManager.GetPeers(ctx)
	if err != nil {
		return false, "Error: Failed to fetch BGP peers"
	}

	if len(peers) == 0 {
		return false, "Status Failure: No BGP peers configured"
	}

	establishedCount := 0
	var notEstablishedPeers []string

	for _, peer := range peers {
		if peer == nil {
			continue
		}
		if peer.SessionState == types.SessionEstablished.String() {
			establishedCount++
		} else {
			// Use peer address if available, otherwise use index
			if peer.PeerAddress != "" {
				notEstablishedPeers = append(notEstablishedPeers, peer.PeerAddress)
			} else {
				notEstablishedPeers = append(notEstablishedPeers, "unknown-peer")
			}
		}
	}

	switch mode {
	case "all":
		if establishedCount == len(peers) {
			return true, fmt.Sprintf("Status OK: All %d BGP peers established", len(peers))
		}
		return false, fmt.Sprintf("Status Failure: %d/%d peers established. Not ready: %v",
			establishedCount, len(peers), notEstablishedPeers)
	case "any":
		fallthrough
	default:
		if establishedCount > 0 {
			return true, fmt.Sprintf("Status OK: %d/%d BGP peers established", establishedCount, len(peers))
		}
		return false, fmt.Sprintf("Status Failure: No BGP peers established (0/%d)", len(peers))
	}
}
