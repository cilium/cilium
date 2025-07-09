// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package healthcheck

import (
	"context"
	"github.com/cilium/cilium/pkg/bgpv1/agent"
	"github.com/cilium/cilium/pkg/bgpv1/types"
)

type BgpStatusGetter interface {
	GetBGPPeerStatus(ctx context.Context) (bool, string)
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
	isReady       bool
}

func (h *healthchecker) GetBGPPeerStatus(ctx context.Context) (bool, string) {
	if !h.config.BGPReadinessEnabled {
		return true, "BGP health check is not enabled"
	}
	if h.isReady {
		return true, "BGP is already ready"
	}
	peers, err := h.RouterManager.GetPeers(ctx)
	if err != nil {
		return false, "Error: Failed to fetch BGP peers"
	}
	for _, peer := range peers {
		if peer.SessionState == types.SessionEstablished.String() {
			h.isReady = true
			return true, "Status OK: BGP peer established"
		}
	}
	return false, "Status Failure: BGP is not ready"
}
