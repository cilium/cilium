// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package test

import (
	"context"
	"reflect"
	"sort"
	"testing"
	"time"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/bgpv1/types"
	cilium_api_v2alpha1 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/testutils"

	"github.com/stretchr/testify/require"
	meta_v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/pointer"
)

var (
	// maxNeighborTestDuration is allowed time for the Neighbor tests execution
	// (on average we need about 35-40s to finish the tests due to BGP timers etc.)
	maxNeighborTestDuration = 1 * time.Minute
)

// peeringState helper struct containing peering information of BGP neighbor
type peeringState struct {
	peerASN                uint32
	peerAddr               string
	peerSession            string
	holdTimeSeconds        int64 // applied hold time, as negotiated with the peer during the session setup
	gracefulRestartEnabled bool
	gracefulRestartTime    int64 // configured restart time
}

// Test_NeighborAddDel validates neighbor add and delete are working as expected. Test validates this using
// peering status which is reported from BGP control plane.
// Topology - (BGP CP) === (2 x gobgp instances)
func Test_NeighborAddDel(t *testing.T) {
	testutils.PrivilegedTest(t)

	node.SetTestLocalNodeStore()
	defer node.UnsetTestLocalNodeStore()

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
					PeerAddress:          dummies[instance1Link].ipv4.String(),
					PeerASN:              int64(gobgpASN),
					HoldTimeSeconds:      pointer.Int32(9), // must be lower than default (90s) to be applied on the peer
					KeepAliveTimeSeconds: pointer.Int32(1), // must be lower than HoldTime
					AuthSecretRef:        pointer.String("a-secret"),
				},
				{
					PeerAddress:          dummies[instance2Link].ipv4.String(),
					PeerASN:              int64(gobgpASN2),
					HoldTimeSeconds:      pointer.Int32(6), // must be lower than default (90s) to be applied on the peer
					KeepAliveTimeSeconds: pointer.Int32(1), // must be lower than HoldTime
				},
			},
			waitState: []string{"ESTABLISHED"},
			expectedPeerStates: []peeringState{
				{
					peerASN:         gobgpASN,
					peerAddr:        dummies[instance1Link].ipv4.Addr().String(),
					peerSession:     types.SessionEstablished.String(),
					holdTimeSeconds: 9,
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
			description: "update both neighbors",
			neighbors: []cilium_api_v2alpha1.CiliumBGPNeighbor{
				{
					PeerAddress:          dummies[instance1Link].ipv4.String(),
					PeerASN:              int64(gobgpASN),
					HoldTimeSeconds:      pointer.Int32(6), // updated, must be lower than the previous value to be applied on the peer
					KeepAliveTimeSeconds: pointer.Int32(1), // must be lower than HoldTime
					AuthSecretRef:        pointer.String("a-secret"),
				},
				{
					PeerAddress:          dummies[instance2Link].ipv4.String(),
					PeerASN:              int64(gobgpASN2),
					HoldTimeSeconds:      pointer.Int32(3), // updated, must be lower than the previous value to be applied on the peer
					KeepAliveTimeSeconds: pointer.Int32(1), // must be lower than HoldTime
				},
			},
			waitState: []string{"ESTABLISHED"},
			expectedPeerStates: []peeringState{
				{
					peerASN:         gobgpASN,
					peerAddr:        dummies[instance1Link].ipv4.Addr().String(),
					peerSession:     types.SessionEstablished.String(),
					holdTimeSeconds: 6,
				},
				{
					peerASN:         gobgpASN2,
					peerAddr:        dummies[instance2Link].ipv4.Addr().String(),
					peerSession:     types.SessionEstablished.String(),
					holdTimeSeconds: 3,
				},
			},
		},
		{
			description:        "delete both neighbors",
			neighbors:          []cilium_api_v2alpha1.CiliumBGPNeighbor{},
			waitState:          []string{"IDLE", "ACTIVE"},
			expectedPeerStates: nil,
		},
	}

	testCtx, testDone := context.WithTimeout(context.Background(), maxNeighborTestDuration)
	defer testDone()

	// test setup, we configure two gobgp instances here.
	gobgpInstances, fixture, cleanup, err := setup(testCtx, []gobgpConfig{gobgpConfPassword, gobgpConf2}, newFixtureConf())
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
						LocalASN:      int64(ciliumASN),
						ExportPodCIDR: pointer.Bool(true),
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
			outstanding := time.Until(deadline)
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
				return peeringStatesEqual(t, step.expectedPeerStates, runningState)
			}

			// Retry peerStatesMatch once per second until the test context deadline.
			// We may need to retry as remote peer's session state does not have to immediately match our
			// session state (e.g. peer may be already in Established but we still in OpenConfirm
			// until we receive a Keepalive from the peer).
			require.Eventually(t, peerStatesMatch, outstanding, 1*time.Second, step.description)
		})
	}
}

// Test_NeighborGracefulRestart tests graceful restart configuration knobs with single peer.
func Test_NeighborGracefulRestart(t *testing.T) {
	testutils.PrivilegedTest(t)

	node.SetTestLocalNodeStore()
	defer node.UnsetTestLocalNodeStore()

	var steps = []struct {
		description       string
		neighbor          cilium_api_v2alpha1.CiliumBGPNeighbor
		waitState         []string
		expectedPeerState peeringState
	}{
		{
			description: "add neighbor with defaults",
			neighbor: cilium_api_v2alpha1.CiliumBGPNeighbor{
				PeerAddress: dummies[instance1Link].ipv4.String(),
				PeerASN:     int64(gobgpASN),
			},
			waitState: []string{"ESTABLISHED"},
			expectedPeerState: peeringState{
				peerASN:     gobgpASN,
				peerAddr:    dummies[instance1Link].ipv4.Addr().String(),
				peerSession: types.SessionEstablished.String(),
			},
		},
		{
			description: "update graceful restart with defaults",
			neighbor: cilium_api_v2alpha1.CiliumBGPNeighbor{
				PeerAddress: dummies[instance1Link].ipv4.String(),
				PeerASN:     int64(gobgpASN),
				GracefulRestart: &cilium_api_v2alpha1.CiliumBGPNeighborGracefulRestart{
					Enabled: true,
				},
			},
			waitState: []string{"ESTABLISHED"},
			expectedPeerState: peeringState{
				peerASN:                gobgpASN,
				peerAddr:               dummies[instance1Link].ipv4.Addr().String(),
				peerSession:            types.SessionEstablished.String(),
				gracefulRestartEnabled: true,
				gracefulRestartTime:    int64(cilium_api_v2alpha1.DefaultBGPGRRestartTimeSeconds),
			},
		},
		{
			description: "update graceful restart, restart time",
			neighbor: cilium_api_v2alpha1.CiliumBGPNeighbor{
				PeerAddress: dummies[instance1Link].ipv4.String(),
				PeerASN:     int64(gobgpASN),
				GracefulRestart: &cilium_api_v2alpha1.CiliumBGPNeighborGracefulRestart{
					Enabled:            true,
					RestartTimeSeconds: pointer.Int32(20),
				},
			},
			waitState: []string{"ESTABLISHED"},
			expectedPeerState: peeringState{
				peerASN:                gobgpASN,
				peerAddr:               dummies[instance1Link].ipv4.Addr().String(),
				peerSession:            types.SessionEstablished.String(),
				gracefulRestartEnabled: true,
				gracefulRestartTime:    20,
			},
		},
		{
			description: "disable graceful restart",
			neighbor: cilium_api_v2alpha1.CiliumBGPNeighbor{
				PeerAddress: dummies[instance1Link].ipv4.String(),
				PeerASN:     int64(gobgpASN),
				GracefulRestart: &cilium_api_v2alpha1.CiliumBGPNeighborGracefulRestart{
					Enabled: false,
				},
			},
			waitState: []string{"ESTABLISHED"},
			expectedPeerState: peeringState{
				peerASN:                gobgpASN,
				peerAddr:               dummies[instance1Link].ipv4.Addr().String(),
				peerSession:            types.SessionEstablished.String(),
				gracefulRestartEnabled: false,
			},
		},
	}

	// This test run can take upto a minute
	testCtx, testDone := context.WithTimeout(context.Background(), maxGracefulRestartTestDuration)
	defer testDone()

	// test setup, we configure single gobgp instance here.
	gobgpInstances, fixture, cleanup, err := setup(testCtx, []gobgpConfig{gobgpConf}, newFixtureConf())
	require.NoError(t, err)
	require.Len(t, gobgpInstances, 1)
	defer cleanup()

	for _, step := range steps {
		t.Run(step.description, func(t *testing.T) {
			// update bgp policy with neighbors defined in test step
			policyObj := newPolicyObj(policyConfig{
				nodeSelector: labels,
				virtualRouters: []cilium_api_v2alpha1.CiliumBGPVirtualRouter{
					{
						LocalASN:      int64(ciliumASN),
						ExportPodCIDR: pointer.Bool(true),
						Neighbors:     []cilium_api_v2alpha1.CiliumBGPNeighbor{step.neighbor},
					},
				},
			})
			_, err = fixture.policyClient.Update(testCtx, &policyObj, meta_v1.UpdateOptions{})
			require.NoError(t, err)

			// wait for peers to reach expected state
			err = gobgpInstances[0].waitForSessionState(testCtx, step.waitState)
			require.NoError(t, err)

			deadline, _ := testCtx.Deadline()
			outstanding := time.Until(deadline)
			require.Greater(t, outstanding, 0*time.Second, "test context deadline exceeded")

			peerStatesMatch := func() bool {
				// validate expected state vs state reported by BGP CP
				var peers []*models.BgpPeer
				peers, err = fixture.bgp.BGPMgr.GetPeers(testCtx)
				require.NoError(t, err, step.description)
				require.Len(t, peers, 1)

				runningPeerState := peeringState{
					peerASN:                uint32(peers[0].PeerAsn),
					peerAddr:               peers[0].PeerAddress,
					peerSession:            peers[0].SessionState,
					gracefulRestartEnabled: peers[0].GracefulRestart.Enabled,
					gracefulRestartTime:    peers[0].GracefulRestart.RestartTimeSeconds,
				}
				return peeringStatesEqual(t, []peeringState{step.expectedPeerState}, []peeringState{runningPeerState})
			}

			// Retry peerStatesMatch once per second until the test context deadline.
			// We may need to retry as remote peer's session state does not have to immediately match our
			// session state (e.g. peer may be already in Established but we still in OpenConfirm
			// until we receive a Keepalive from the peer).
			require.Eventually(t, peerStatesMatch, outstanding, 1*time.Second)
		})
	}
}

func peeringStatesEqual(t *testing.T, expected, actual []peeringState) bool {
	sort.Slice(expected, func(i, j int) bool {
		return expected[i].peerASN < expected[j].peerASN
	})
	sort.Slice(actual, func(i, j int) bool {
		return actual[i].peerASN < actual[j].peerASN
	})
	equal := reflect.DeepEqual(expected, actual)
	if !equal {
		t.Logf("peering states not (yet) equal - expected: %v, actual: %v", expected, actual)
	}
	return equal
}
