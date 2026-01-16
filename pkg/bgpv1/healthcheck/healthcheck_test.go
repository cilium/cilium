// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package healthcheck

import (
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/bgpv1/agent"
	"github.com/cilium/cilium/pkg/bgpv1/types"
)

// mockBGPRouterManager is a mock implementation of the BGPRouterManager interface for testing.
type mockBGPRouterManager struct {
	agent.BGPRouterManager
	peers []*models.BgpPeer
	err   error
}

func (m *mockBGPRouterManager) GetPeers(ctx context.Context) ([]*models.BgpPeer, error) {
	return m.peers, m.err
}

func TestGetBGPPeerStatusWithMode(t *testing.T) {
	// establishedPeers contains a list of two established BGP peers.
	establishedPeers := []*models.BgpPeer{
		{
			PeerAddress:  "192.168.0.1",
			PeerAsn:      64512,
			SessionState: types.SessionEstablished.String(),
		},
		{
			PeerAddress:  "192.168.0.2",
			PeerAsn:      64513,
			SessionState: types.SessionEstablished.String(),
		},
	}

	// mixedPeers contains one established peer and one idle peer.
	mixedPeers := []*models.BgpPeer{
		{
			PeerAddress:  "192.168.0.1",
			PeerAsn:      64512,
			SessionState: types.SessionEstablished.String(),
		},
		{
			PeerAddress:  "192.168.0.2",
			PeerAsn:      64513,
			SessionState: "Idle",
		},
	}

	// noEstablishedPeers contains a list of peers with none established.
	noEstablishedPeers := []*models.BgpPeer{
		{
			PeerAddress:  "192.168.0.1",
			PeerAsn:      64512,
			SessionState: "Idle",
		},
		{
			PeerAddress:  "192.168.0.2",
			PeerAsn:      64513,
			SessionState: "Connect",
		},
	}

	tests := []struct {
		name           string
		mode           string
		requireBGP     bool
		peers          []*models.BgpPeer
		managerErr     error
		expectedOK     bool
		expectedStatus string
	}{
		{
			name:           "BGP not required",
			requireBGP:     false,
			expectedOK:     true,
			expectedStatus: "BGP health check is not required",
		},
		{
			name:           "Router manager not available",
			requireBGP:     true,
			managerErr:     fmt.Errorf("manager not available"),
			expectedOK:     false,
			expectedStatus: "Error: BGP router manager not available",
		},
		{
			name:           "No peers configured",
			requireBGP:     true,
			peers:          []*models.BgpPeer{},
			expectedOK:     false,
			expectedStatus: "Status Failure: No BGP peers configured",
		},
		{
			name:           "All peers established with 'all' mode",
			mode:           "all",
			requireBGP:     true,
			peers:          establishedPeers,
			expectedOK:     true,
			expectedStatus: "Status OK: All 2 BGP peers established",
		},
		{
			name:           "Not all peers established with 'all' mode",
			mode:           "all",
			requireBGP:     true,
			peers:          mixedPeers,
			expectedOK:     false,
			expectedStatus: "Status Failure: 1/2 peers established. Not ready: [192.168.0.2]",
		},
		{
			name:           "At least one peer established with 'any' mode",
			mode:           "any",
			requireBGP:     true,
			peers:          mixedPeers,
			expectedOK:     true,
			expectedStatus: "Status OK: 1/2 BGP peers established",
		},
		{
			name:           "No peers established with 'any' mode",
			mode:           "any",
			requireBGP:     true,
			peers:          noEstablishedPeers,
			expectedOK:     false,
			expectedStatus: "Status Failure: No BGP peers established (0/2)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockManager := &mockBGPRouterManager{
				peers: tt.peers,
				err:   tt.managerErr,
			}

			// In cases where the manager is supposed to be nil
			var checker BgpStatusGetter
			if tt.name == "Router manager not available" {
				checker = &healthchecker{
					RouterManager: nil, // Explicitly nil
					config:        Config{},
				}
			} else {
				checker = &healthchecker{
					RouterManager: mockManager,
					config:        Config{},
				}
			}

			ok, status := checker.GetBGPPeerStatusWithMode(context.Background(), tt.mode, tt.requireBGP)

			require.Equal(t, tt.expectedOK, ok, "unexpected health status")
			require.Equal(t, tt.expectedStatus, status, "unexpected status message")
		})
	}
}
