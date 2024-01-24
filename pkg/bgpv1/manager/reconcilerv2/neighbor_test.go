// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package reconcilerv2

import (
	"context"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"

	"github.com/cilium/cilium/pkg/bgpv1/manager/instance"
	"github.com/cilium/cilium/pkg/bgpv1/manager/store"
	"github.com/cilium/cilium/pkg/bgpv1/types"
	"github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	"github.com/cilium/cilium/pkg/k8s/resource"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/option"
)

type checks struct {
	holdTimer         bool
	connectRetryTimer bool
	keepaliveTimer    bool
	grRestartTime     bool
}

var (
	peer1 = PeerData{
		Peer: &v2alpha1.CiliumBGPNodePeer{
			Name:        "peer-1",
			PeerAddress: ptr.To[string]("192.168.0.1"),
			PeerASN:     ptr.To[int64](64124),
			PeerConfigRef: &v2alpha1.PeerConfigReference{
				Group: "cilium.io",
				Kind:  v2alpha1.BGPPCKindDefinition,
				Name:  "peer-config",
			},
		},
		Config: &v2alpha1.CiliumBGPPeerConfigSpec{
			Transport: &v2alpha1.CiliumBGPTransport{
				LocalPort: ptr.To[int32](v2alpha1.DefaultBGPPeerLocalPort),
				PeerPort:  ptr.To[int32](v2alpha1.DefaultBGPPeerPort),
			},
		},
	}

	peer2 = PeerData{
		Peer: &v2alpha1.CiliumBGPNodePeer{
			Name:        "peer-2",
			PeerAddress: ptr.To[string]("192.168.0.2"),
			PeerASN:     ptr.To[int64](64124),
			PeerConfigRef: &v2alpha1.PeerConfigReference{
				Group: "cilium.io",
				Kind:  v2alpha1.BGPPCKindDefinition,
				Name:  "peer-config",
			},
		},
		Config: &v2alpha1.CiliumBGPPeerConfigSpec{
			Transport: &v2alpha1.CiliumBGPTransport{
				LocalPort: ptr.To[int32](v2alpha1.DefaultBGPPeerLocalPort),
				PeerPort:  ptr.To[int32](v2alpha1.DefaultBGPPeerPort),
			},
		},
	}

	peer2UpdatedTimers = func() PeerData {
		peer2Copy := PeerData{
			Peer:     peer2.Peer.DeepCopy(),
			Config:   peer2.Config.DeepCopy(),
			Password: peer2.Password,
		}

		peer2Copy.Config.Timers = &v2alpha1.CiliumBGPTimers{
			ConnectRetryTimeSeconds: ptr.To[int32](3),
			HoldTimeSeconds:         ptr.To[int32](9),
			KeepAliveTimeSeconds:    ptr.To[int32](3),
		}

		return peer2Copy
	}()

	peer2UpdatedPorts = func() PeerData {
		peer2Copy := PeerData{
			Peer:     peer2.Peer.DeepCopy(),
			Config:   peer2.Config.DeepCopy(),
			Password: peer2.Password,
		}

		peer2Copy.Config.Transport = &v2alpha1.CiliumBGPTransport{
			LocalPort: ptr.To[int32](1790),
			PeerPort:  ptr.To[int32](1790),
		}

		return peer2Copy
	}()

	peer2UpdatedGR = func() PeerData {
		peer2Copy := PeerData{
			Peer:     peer2.Peer.DeepCopy(),
			Config:   peer2.Config.DeepCopy(),
			Password: peer2.Password,
		}

		peer2Copy.Config.GracefulRestart = &v2alpha1.CiliumBGPNeighborGracefulRestart{
			Enabled:            true,
			RestartTimeSeconds: ptr.To[int32](3),
		}

		return peer2Copy
	}()

	peer2Pass = func() PeerData {
		peer2Copy := PeerData{
			Peer:     peer2.Peer.DeepCopy(),
			Config:   peer2.Config.DeepCopy(),
			Password: peer2.Password,
		}

		peer2Copy.Config.AuthSecretRef = ptr.To[string]("a-secret")
		peer2Copy.Password = "a-password"

		return peer2Copy
	}()

	peer2UpdatePass = func() PeerData {
		peer2Copy := PeerData{
			Peer:     peer2.Peer.DeepCopy(),
			Config:   peer2.Config.DeepCopy(),
			Password: peer2.Password,
		}

		peer2Copy.Config.AuthSecretRef = ptr.To[string]("a-secret")
		peer2Copy.Password = "b-password"

		return peer2Copy
	}()
)

func FakeSecretStore(secrets map[string][]byte) store.BGPCPResourceStore[*slim_corev1.Secret] {
	store := store.NewMockBGPCPResourceStore[*slim_corev1.Secret]()
	for k, v := range secrets {
		store.Upsert(&slim_corev1.Secret{
			ObjectMeta: slim_metav1.ObjectMeta{
				Namespace: "bgp-secrets",
				Name:      k,
			},
			Data: map[string]slim_corev1.Bytes{"password": slim_corev1.Bytes(v)},
		})
	}
	return store
}

func FakePeerConfigStore(objects []*v2alpha1.CiliumBGPPeerConfig) store.BGPCPResourceStore[*v2alpha1.CiliumBGPPeerConfig] {
	store := store.NewMockBGPCPResourceStore[*v2alpha1.CiliumBGPPeerConfig]()
	for _, obj := range objects {
		store.Upsert(obj)
	}
	return store
}

// TestNeighborReconciler confirms the `neighborReconciler` function configures
// the desired BGP neighbors given a CiliumBGPVirtualRouter configuration.
func TestNeighborReconciler(t *testing.T) {
	req := require.New(t)

	table := []struct {
		name         string
		neighbors    []PeerData
		newNeighbors []PeerData
		secretStore  resource.Store[*slim_corev1.Secret]
		checks       checks
		err          error
	}{
		{
			name:         "no change",
			neighbors:    []PeerData{peer1, peer2},
			newNeighbors: []PeerData{peer1, peer2},
			err:          nil,
		},
		{
			name:         "add peers",
			neighbors:    []PeerData{peer1},
			newNeighbors: []PeerData{peer1, peer2},
			err:          nil,
		},
		{
			name:         "remove peers",
			neighbors:    []PeerData{peer1, peer2},
			newNeighbors: []PeerData{peer1},
			err:          nil,
		},
		{
			name:         "update config : timers",
			neighbors:    []PeerData{peer1, peer2},
			newNeighbors: []PeerData{peer1, peer2UpdatedTimers},
			err:          nil,
		},
		{
			name:         "update config : ports",
			neighbors:    []PeerData{peer1, peer2},
			newNeighbors: []PeerData{peer1, peer2UpdatedPorts},
			err:          nil,
		},
		{
			name:         "update config : graceful restart",
			neighbors:    []PeerData{peer1, peer2},
			newNeighbors: []PeerData{peer1, peer2UpdatedGR},
			err:          nil,
		},
		{
			name:         "update config : password",
			neighbors:    []PeerData{peer2},
			newNeighbors: []PeerData{peer2Pass},
			err:          nil,
		},
		{
			name:         "update config : password updated",
			neighbors:    []PeerData{peer2Pass},
			newNeighbors: []PeerData{peer2UpdatePass},
			err:          nil,
		},
		{
			name:         "update config : password removed",
			neighbors:    []PeerData{peer2Pass},
			newNeighbors: []PeerData{peer2},
			err:          nil,
		},
	}
	for _, tt := range table {
		t.Run(tt.name, func(t *testing.T) {
			// our test BgpServer with our original router ID and local port
			srvParams := types.ServerParameters{
				Global: types.BGPGlobal{
					ASN:        64125,
					RouterID:   "127.0.0.1",
					ListenPort: -1,
				},
			}

			testInstance, err := instance.NewBGPInstance(context.Background(), logrus.WithField("unit_test", tt.name), srvParams)
			req.NoError(err)

			t.Cleanup(func() {
				testInstance.Router.Stop()
			})

			params, nodeConfig := setupNeighbors(tt.neighbors)

			// setup initial neighbors
			neighborReconciler := NewNeighborReconciler(params).Reconciler
			reconcileParams := ReconcileParams{
				BGPInstance:   testInstance,
				DesiredConfig: nodeConfig,
			}
			err = neighborReconciler.Reconcile(context.Background(), reconcileParams)
			req.NoError(err)

			// validate neighbors
			validatePeers(req, tt.neighbors, getRunningPeers(req, testInstance), tt.checks)

			// update neighbors
			params, nodeConfig = setupNeighbors(tt.newNeighbors)
			neighborReconciler = NewNeighborReconciler(params).Reconciler
			reconcileParams = ReconcileParams{
				BGPInstance:   testInstance,
				DesiredConfig: nodeConfig,
			}
			err = neighborReconciler.Reconcile(context.Background(), reconcileParams)
			req.NoError(err)

			// validate neighbors
			validatePeers(req, tt.newNeighbors, getRunningPeers(req, testInstance), tt.checks)
		})
	}
}

func setupNeighbors(peers []PeerData) (NeighborReconcilerIn, *v2alpha1.CiliumBGPNodeInstance) {
	// Desired BGP Node config
	nodeConfig := &v2alpha1.CiliumBGPNodeInstance{
		Name: "bgp-node",
	}

	// setup fake store for peer config
	var objects []*v2alpha1.CiliumBGPPeerConfig
	for _, p := range peers {
		obj := &v2alpha1.CiliumBGPPeerConfig{
			ObjectMeta: metav1.ObjectMeta{
				Name: p.Peer.PeerConfigRef.Name,
			},
			Spec: *p.Config.DeepCopy(),
		}
		objects = append(objects, obj)
		nodeConfig.Peers = append(nodeConfig.Peers, *p.Peer)
	}
	peerConfigStore := FakePeerConfigStore(objects)

	// setup secret store
	secrets := make(map[string][]byte)
	for _, p := range peers {
		if p.Config.AuthSecretRef != nil {
			secrets[*p.Config.AuthSecretRef] = []byte(p.Password)
		}
	}
	secretStore := FakeSecretStore(secrets)

	return NeighborReconcilerIn{
		Logger:       logrus.WithField("unit_test", "neighbors"),
		SecretStore:  secretStore,
		PeerConfig:   peerConfigStore,
		DaemonConfig: &option.DaemonConfig{BGPSecretsNamespace: "bgp-secrets"},
	}, nodeConfig
}

func validatePeers(req *require.Assertions, expected, running []PeerData, checks checks) {
	req.Equal(len(expected), len(running))

	for _, expPeer := range expected {
		found := false
		for _, runPeer := range running {
			req.NotNil(runPeer.Peer.PeerAddress)
			req.NotNil(runPeer.Peer.PeerASN)

			if *expPeer.Peer.PeerAddress == *runPeer.Peer.PeerAddress && *expPeer.Peer.PeerASN == *runPeer.Peer.PeerASN {
				found = true

				if checks.holdTimer {
					req.Equal(*expPeer.Config.Timers.HoldTimeSeconds, *runPeer.Config.Timers.HoldTimeSeconds)
				}

				if checks.connectRetryTimer {
					req.Equal(*expPeer.Config.Timers.ConnectRetryTimeSeconds, *runPeer.Config.Timers.ConnectRetryTimeSeconds)
				}

				if checks.keepaliveTimer {
					req.Equal(*expPeer.Config.Timers.KeepAliveTimeSeconds, *runPeer.Config.Timers.KeepAliveTimeSeconds)
				}

				if checks.grRestartTime {
					req.Equal(expPeer.Config.GracefulRestart.Enabled, runPeer.Config.GracefulRestart.Enabled)
					req.Equal(*expPeer.Config.GracefulRestart.RestartTimeSeconds, *runPeer.Config.GracefulRestart.RestartTimeSeconds)
				}

				if expPeer.Password != "" {
					req.NotEmpty(runPeer.Password)
				}

				break
			}
		}
		req.True(found)
	}
}

func getRunningPeers(req *require.Assertions, instance *instance.BGPInstance) []PeerData {
	getPeerResp, err := instance.Router.GetPeerState(context.Background())
	req.NoError(err)

	var runningPeers []PeerData
	for _, peer := range getPeerResp.Peers {
		peerObj := &v2alpha1.CiliumBGPNodePeer{
			PeerAddress: ptr.To[string](peer.PeerAddress),
			PeerASN:     ptr.To[int64](peer.PeerAsn),
		}

		peerConfObj := &v2alpha1.CiliumBGPPeerConfigSpec{
			Transport: &v2alpha1.CiliumBGPTransport{
				PeerPort: ptr.To[int32](int32(peer.PeerPort)),
			},
			Timers: &v2alpha1.CiliumBGPTimers{
				ConnectRetryTimeSeconds: ptr.To[int32](int32(peer.ConnectRetryTimeSeconds)),
				HoldTimeSeconds:         ptr.To[int32](int32(peer.ConfiguredHoldTimeSeconds)),
				KeepAliveTimeSeconds:    ptr.To[int32](int32(peer.ConfiguredKeepAliveTimeSeconds)),
			},
			GracefulRestart: &v2alpha1.CiliumBGPNeighborGracefulRestart{
				Enabled:            peer.GracefulRestart.Enabled,
				RestartTimeSeconds: ptr.To[int32](int32(peer.GracefulRestart.RestartTimeSeconds)),
			},
			EBGPMultihop: ptr.To[int32](int32(peer.EbgpMultihopTTL)),
		}

		password := ""
		if peer.TCPPasswordEnabled {
			password = "something-is-set-dont-care-what"
		}

		runningPeers = append(runningPeers, PeerData{
			Peer:     peerObj,
			Config:   peerConfObj,
			Password: password,
		})
	}
	return runningPeers
}
