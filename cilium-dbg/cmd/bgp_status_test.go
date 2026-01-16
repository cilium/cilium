// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"bytes"
	"os"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/api/v1/client/bgp"
	"github.com/cilium/cilium/api/v1/client/daemon"
	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/bgpv1/types"
	clientPkg "github.com/cilium/cilium/pkg/client"
)

// mockDaemonClient mocks the daemon API for GetHealthz.
type mockDaemonClient struct {
	daemon.ClientService
	getHealthz func(params *daemon.GetHealthzParams, opts ...daemon.ClientOption) (*daemon.GetHealthzOK, error)
}

func (c *mockDaemonClient) GetHealthz(params *daemon.GetHealthzParams, opts ...daemon.ClientOption) (*daemon.GetHealthzOK, error) {
	return c.getHealthz(params, opts...)
}

// mockBgpClient mocks the BGP API for GetBgpPeers.
type mockBgpClient struct {
	bgp.ClientService
	getBgpPeers func(params *bgp.GetBgpPeersParams, opts ...bgp.ClientOption) (*bgp.GetBgpPeersOK, error)
}

func (c *mockBgpClient) GetBgpPeers(params *bgp.GetBgpPeersParams, opts ...bgp.ClientOption) (*bgp.GetBgpPeersOK, error) {
	return c.getBgpPeers(params, opts...)
}

func TestBgpStatus(t *testing.T) {
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
		args           []string
		bgpPeers       []*models.BgpPeer
		bgpStatus      *models.BGPStatus
		getPeersErr    error
		getHealthzErr  error
		expectedExit   int
		expectedOutput string
	}{
		{
			name:         "all peers established with --require-all",
			args:         []string{"--require-all"},
			bgpPeers:     establishedPeers,
			bgpStatus:    &models.BGPStatus{State: models.BGPStatusStateOk},
			expectedExit: 0,
		},
		{
			name:         "not all peers established with --require-all",
			args:         []string{"--require-all"},
			bgpPeers:     mixedPeers,
			bgpStatus:    &models.BGPStatus{State: models.BGPStatusStateOk},
			expectedExit: 1,
		},
		{
			name:         "at least one peer established with --require-any",
			args:         []string{"--require-any"},
			bgpPeers:     mixedPeers,
			bgpStatus:    &models.BGPStatus{State: models.BGPStatusStateOk},
			expectedExit: 0,
		},
		{
			name:         "no peers established with --require-any",
			args:         []string{"--require-any"},
			bgpPeers:     noEstablishedPeers,
			bgpStatus:    &models.BGPStatus{State: models.BGPStatusStateOk},
			expectedExit: 1,
		},
		{
			name:           "show peers",
			args:           []string{"--show-peers"},
			bgpPeers:       establishedPeers,
			bgpStatus:      &models.BGPStatus{State: models.BGPStatusStateOk},
			expectedExit:   0,
			expectedOutput: "192.168.0.1",
		},
		{
			name:           "bgp disabled",
			args:           []string{"--show-peers"}, // need to trigger the GetBgpPeers call
			getPeersErr:    bgp.NewGetBgpPeersDisabled(),
			bgpStatus:      &models.BGPStatus{State: models.BGPStatusStateDisabled},
			expectedExit:   0,
			expectedOutput: "BGP Control Plane is disabled",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Mock BGP client
			bgpClient := &mockBgpClient{
				getBgpPeers: func(params *bgp.GetBgpPeersParams, opts ...bgp.ClientOption) (*bgp.GetBgpPeersOK, error) {
					if tt.getPeersErr != nil {
						return nil, tt.getPeersErr
					}
					return &bgp.GetBgpPeersOK{Payload: tt.bgpPeers}, nil
				},
			}

			// Mock daemon client
			daemonClient := &mockDaemonClient{
				getHealthz: func(params *daemon.GetHealthzParams, opts ...daemon.ClientOption) (*daemon.GetHealthzOK, error) {
					if tt.getHealthzErr != nil {
						return nil, tt.getHealthzErr
					}
					return &daemon.GetHealthzOK{Payload: &models.StatusResponse{BgpStatus: tt.bgpStatus}}, nil
				},
			}

			// Mock Cilium client
			ciliumClient := &clientPkg.Client{}
			ciliumClient.Daemon = daemonClient
			ciliumClient.Bgp = bgpClient

			// Capture output and exit code
			var exitCode int
			var output bytes.Buffer
			runBgpStatusWithMocks(ciliumClient, tt.args, &output, func(code int) {
				exitCode = code
			})

			require.Equal(t, tt.expectedExit, exitCode, "unexpected exit code")
			if tt.expectedOutput != "" {
				require.Contains(t, output.String(), tt.expectedOutput, "unexpected output")
			}
		})
	}
}

var osExit = os.Exit

// runBgpStatusWithMocks executes the BGP status command with mocked clients and captures the exit code.
func runBgpStatusWithMocks(c *clientPkg.Client, args []string, output *bytes.Buffer, exitFunc func(int)) {
	// Save original client and restore after the test
	origClient := client
	// Save original flag values
	origRequireAll := requireAll
	origRequireAny := requireAny
	origShowPeers := showPeers
	defer func() {
		client = origClient
		requireAll = origRequireAll
		requireAny = origRequireAny
		showPeers = origShowPeers
		BgpStatusCmd.ResetFlags()
	}()

	// Set mocked client
	client = c

	// Reset flags to default values
	requireAll = false
	requireAny = false
	showPeers = false

	// Reset and set flags for the command
	BgpStatusCmd.ResetFlags()
	BgpStatusCmd.Flags().BoolVar(&requireAll, "require-all", false, "Require all BGP peers to be in Established state")
	BgpStatusCmd.Flags().BoolVar(&requireAny, "require-any", false, "Require at least one BGP peer to be in Established state")
	BgpStatusCmd.Flags().BoolVar(&showPeers, "show-peers", false, "Show detailed information about BGP peers")

	// Parse the flags from args - this is the key step that was missing!
	if err := BgpStatusCmd.ParseFlags(args); err != nil {
		exitFunc(1)
		return
	}

	// Execute the command's Run function with the output buffer
	if err := runBgpStatusWithWriter(output); err != nil {
		exitFunc(1)
	} else {
		exitFunc(0)
	}
}
