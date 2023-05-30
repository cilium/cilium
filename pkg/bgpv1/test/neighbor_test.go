// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package test

import (
	"context"
	"testing"
	"time"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/bgpv1/types"
	cilium_api_v2alpha1 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	"github.com/cilium/cilium/pkg/testutils"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	meta_v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// peeringState helper struct containing peering information of BGP neighbor
type peeringState struct {
	peerASN         uint32
	peerAddr        string
	peerSession     string
	holdTimeSeconds int64 // applied hold time, as negotiated with the peer during the session setup
}

// Test_NeighborAddDel validates neighbor add and delete are working as expected. Test validates this using
// peering status which is reported from BGP control plane.
// Topology - (BGP CP) === (2 x gobgp instances)
func Test_NeighborAddDel(t *testing.T) {
	testutils.PrivilegedTest(t)

	var steps = []struct {
		description        string
		neighbors          []cilium_api_v2alpha1.CiliumBGPNeighbor
		waitState          []string
		expectedPeerStates []peeringState
	}{
		{
			description: "add two neighbors",
			neighbors: []cilium_api_v2alpha1.CiliumBGPNeighbor{
				{
					PeerAddress: dummies[instance1Link].ipv4.String(),
					PeerASN:     int(gobgpASN),
					HoldTime:    meta_v1.Duration{Duration: 3 * time.Second}, // must be lower than default (90s) to be applied on the peer
				},
				{
					PeerAddress: dummies[instance2Link].ipv4.String(),
					PeerASN:     int(gobgpASN2),
					HoldTime:    meta_v1.Duration{Duration: 6 * time.Second}, // must be lower than default (90s) to be applied on the peer
				},
			},
			waitState: []string{"ESTABLISHED"},
			expectedPeerStates: []peeringState{
				{
					peerASN:         gobgpASN,
					peerAddr:        dummies[instance1Link].ipv4.Addr().String(),
					peerSession:     types.SessionEstablished.String(),
					holdTimeSeconds: 3,
				},
				{
					peerASN:         gobgpASN2,
					peerAddr:        dummies[instance2Link].ipv4.Addr().String(),
					peerSession:     types.SessionEstablished.String(),
					holdTimeSeconds: 6,
				},
			},
		},
		{
			description:        "delete both neighbors",
			neighbors:          []cilium_api_v2alpha1.CiliumBGPNeighbor{},
			waitState:          []string{"IDLE", "ACTIVE"},
			expectedPeerStates: []peeringState{},
		},
	}

	testCtx, testDone := context.WithTimeout(context.Background(), maxTestDuration)
	defer testDone()

	// test setup, we configure two gobgp instances here.
	gobgpInstances, fixture, cleanup, err := setup(testCtx, []gobgpConfig{gobgpConf, gobgpConf2}, fixtureConf)
	require.NoError(t, err)
	require.Len(t, gobgpInstances, 2)
	defer cleanup()

	for _, step := range steps {
		t.Run(step.description, func(t *testing.T) {
			// update bgp policy with neighbors defined in test step
			policyObj := newPolicyObj(policyConfig{
				nodeSelector: labels,
				virtualRouters: []cilium_api_v2alpha1.CiliumBGPVirtualRouter{
					{
						LocalASN:      int(ciliumASN),
						ExportPodCIDR: true,
						Neighbors:     step.neighbors,
					},
				},
			})
			_, err = fixture.policyClient.Update(testCtx, &policyObj, meta_v1.UpdateOptions{})
			require.NoError(t, err, step.description)

			// wait for peers to reach expected state
			for _, gobgpInstance := range gobgpInstances {
				err = gobgpInstance.waitForSessionState(testCtx, step.waitState)
				require.NoError(t, err, step.description)
			}

			deadline, _ := testCtx.Deadline()
			outstanding := deadline.Sub(time.Now())
			require.Greater(t, outstanding, 0*time.Second, "test context deadline exceeded")

			peerStatesMatch := func() bool {
				// validate expected state vs state reported by BGP CP
				var peers []*models.BgpPeer
				peers, err = fixture.bgp.BGPMgr.GetPeers(testCtx)
				require.NoError(t, err, step.description)

				var runningState []peeringState
				for _, peer := range peers {
					runningState = append(runningState, peeringState{
						peerASN:         uint32(peer.PeerAsn),
						peerAddr:        peer.PeerAddress,
						peerSession:     peer.SessionState,
						holdTimeSeconds: peer.AppliedHoldTimeSeconds,
					})
				}
				return assert.ElementsMatch(t, step.expectedPeerStates, runningState, step.description)
			}

			// Retry peerStatesMatch once per second until the test context deadline.
			// We may need to retry as remote peer's session state does not have to immediately match our
			// session state (e.g. peer may be already in Established but we still in OpenConfirm
			// until we receive a Keepalive from the peer).
			require.Eventually(t, peerStatesMatch, outstanding, 1*time.Second, step.description)
		})
	}
}
