// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package agent

import (
	"log/slog"
	"net"
	"testing"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netlink"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/hivetest"
	"github.com/cilium/statedb"

	cnicell "github.com/cilium/cilium/daemon/cmd/cni"
	fakecni "github.com/cilium/cilium/daemon/cmd/cni/fake"
	"github.com/cilium/cilium/daemon/k8s"
	"github.com/cilium/cilium/pkg/clustermesh"
	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/datapath/iptables/ipset"
	"github.com/cilium/cilium/pkg/datapath/linux/safenetlink"
	"github.com/cilium/cilium/pkg/datapath/linux/sysctl"
	"github.com/cilium/cilium/pkg/datapath/tables"
	"github.com/cilium/cilium/pkg/datapath/tunnel"
	"github.com/cilium/cilium/pkg/dial"
	"github.com/cilium/cilium/pkg/endpoint/regeneration"
	envoyCfg "github.com/cilium/cilium/pkg/envoy/config"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/identity/cache"
	"github.com/cilium/cilium/pkg/ipcache"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client/testutils"
	k8sSynced "github.com/cilium/cilium/pkg/k8s/synced"
	"github.com/cilium/cilium/pkg/k8s/watchers"
	"github.com/cilium/cilium/pkg/kvstore"
	"github.com/cilium/cilium/pkg/kvstore/store"
	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/loadbalancer/writer"
	"github.com/cilium/cilium/pkg/mtu"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/node/addressing"
	nodeManager "github.com/cilium/cilium/pkg/node/manager"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
	"github.com/cilium/cilium/pkg/nodediscovery"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/source"
	"github.com/cilium/cilium/pkg/testutils"
	identityTestutils "github.com/cilium/cilium/pkg/testutils/identity"
	"github.com/cilium/cilium/pkg/testutils/netns"
	"github.com/cilium/cilium/pkg/time"
	"github.com/cilium/cilium/pkg/wireguard/types"
)

var TestTimeout = 5 * time.Second

// paramsOut holds the output parameters needed for running cells in the test.
type paramsOut struct {
	cell.Out

	WireguardConfig       Config
	TunnelConfig          tunnel.Config
	DaemonConfig          *option.DaemonConfig
	LBConfig              loadbalancer.Config
	LBExternalConfig      loadbalancer.ExternalConfig
	LocalNode             node.LocalNode
	IPCache               *ipcache.IPCache
	CNIConfigManager      cnicell.CNIConfigManager
	K8SAPIGroups          *k8sSynced.APIGroups
	K8SResources          *k8sSynced.Resources
	Sysctl                sysctl.Sysctl
	StoreFactory          store.Factory
	ClusterMeshMetrics    clustermesh.ClusterMeshMetrics
	RemoteIdentityWatcher clustermesh.RemoteIdentityWatcher
	CacheStatus           k8sSynced.CacheStatus
	ClusterInfo           cmtypes.ClusterInfo
}

func TestPrivileged_TestWireGuardCell(t *testing.T) {
	// Needed to create the test namespace where the agent creates the cilium_wg0 link.
	testutils.PrivilegedTest(t)

	// Create a temporary directory, used also by the agent for the private key.
	testRunDir := t.TempDir()

	// Use the temporary directory in daemon config.
	oldRunDir, oldStateDir := option.Config.RunDir, option.Config.StateDir
	defer func() {
		option.Config.RunDir = oldRunDir
		option.Config.StateDir = oldStateDir
	}()
	option.Config.RunDir = testRunDir
	option.Config.StateDir = testRunDir

	var (
		// Local references are updated when starting the Hive.
		wgAgent       *Agent
		ipCache       *ipcache.IPCache
		nodeStore     *node.LocalNodeStore
		nodeDiscovery *nodediscovery.NodeDiscovery
		manager       nodeManager.NodeManager
		cacheStatus   k8sSynced.CacheStatus

		ctx = t.Context()
		ns  = netns.NewNetNS(t)
		log = hivetest.Logger(t, hivetest.LogLevel(slog.LevelError))
	)

	// getHive returns a new hive with Wireguard enabled/disabled.
	getHive := func(wireguardEnabled bool) *hive.Hive {
		return hive.New(
			mtu.Cell,
			nodeManager.Cell,
			nodediscovery.Cell,
			source.Cell,
			watchers.Cell,
			dial.ServiceResolverCell,
			clustermesh.Cell,
			writer.Cell,
			ipset.Cell,
			k8s.ResourcesCell,
			cell.Config(envoyCfg.SecretSyncConfig{}),
			k8sClient.FakeClientCell(),
			kvstore.Cell(kvstore.DisabledBackendName),
			node.LocalNodeStoreTestCell,

			cell.Provide(
				newWireguardAgent,
				newWireguardConfig,

				regeneration.NewFence,
				tables.NewDeviceTable,
				tables.NewNodeAddressTable,
				ipcache.NewLocalIPIdentityWatcher,
				ipcache.NewIPIdentitySynchronizer,
				statedb.RWTable[*tables.Device].ToTable,
				statedb.RWTable[tables.NodeAddress].ToTable,

				func() paramsOut {
					return paramsOut{
						WireguardConfig: Config{
							UserConfig: UserConfig{
								EnableConfig: EnableConfig{
									EnableWireguard: wireguardEnabled,
								},
								WireguardTrackAllIPsFallback: false,
								WireguardPersistentKeepalive: 0,
								NodeEncryptionOptOutLabels:   "",
							},
							EnableIPv4:       true,
							EnableIPv6:       true,
							StateDir:         testRunDir,
							TunnelingEnabled: false,
							EncryptNode:      false,
						},
						TunnelConfig:     tunnel.Config{},
						DaemonConfig:     option.Config,
						LBConfig:         loadbalancer.Config{},
						LBExternalConfig: loadbalancer.ExternalConfig{},
						LocalNode: node.LocalNode{
							Node: nodeTypes.Node{
								Name: k8s1NodeName,
								IPAddresses: []nodeTypes.Address{
									{
										Type: addressing.NodeInternalIP,
										IP:   k8s1NodeIPv4,
									},
								},
								Annotations: map[string]string{},
							},
						},
						IPCache: ipcache.NewIPCache(&ipcache.Configuration{
							Context:           ctx,
							Logger:            hivetest.Logger(t),
							IdentityAllocator: cache.NewNoopIdentityAllocator(log),
							IdentityUpdater:   &identityTestutils.IdentityAllocatorOwnerMock{},
						}),
						K8SAPIGroups:          &k8sSynced.APIGroups{},
						K8SResources:          &k8sSynced.Resources{},
						CNIConfigManager:      &fakecni.FakeCNIConfigManager{},
						Sysctl:                sysctl.NewDirectSysctl(afero.NewOsFs(), "/proc"),
						StoreFactory:          store.NewFactory(hivetest.Logger(t), store.MetricsProvider()),
						ClusterMeshMetrics:    nil,
						RemoteIdentityWatcher: nil,
						CacheStatus:           make(k8sSynced.CacheStatus),
						ClusterInfo:           cmtypes.DefaultClusterInfo,
					}
				},
			),

			cell.Invoke(
				func(a types.WireguardAgent, n *nodediscovery.NodeDiscovery, s *node.LocalNodeStore, u nodeManager.NodeManager, i *ipcache.IPCache, c k8sSynced.CacheStatus) {
					wgAgent = a.(*Agent)
					nodeDiscovery = n
					manager = u
					nodeStore = s
					ipCache = i
					cacheStatus = c
				}),
		)
	}

	t.Run("WireguardEnabled", func(t *testing.T) {
		ns.Do(func() error {
			// 0. Create a hive with WireGuard enabled.
			hive := getHive(true)

			// 1. Start the hive.
			require.NoError(t, hive.Start(log, ctx))

			// 2. Ensure the wireguard Agent is enabled.
			require.True(t, wgAgent.Enabled())

			// 3. Ensure the link cilium_wg0 has been created.
			link, err := safenetlink.LinkByName(types.IfaceName)
			require.NoError(t, err)

			// 4. Ensure the MTU is set accordingly (mtu-reconciler job).
			require.EventuallyWithT(t, func(c *assert.CollectT) {
				assert.Equal(c, mtu.EthernetMTU-mtu.WireguardOverhead, link.Attrs().MTU)
			}, TestTimeout, 50*time.Millisecond)

			// 5. Ensure local node has been updated (localnode-updater job).
			require.EventuallyWithT(t, func(c *assert.CollectT) {
				localNode, err := nodeStore.Get(ctx)
				require.NoError(c, err)
				assert.NotEmpty(c, localNode.WireguardPubKey)
			}, TestTimeout, 50*time.Millisecond)

			// 6.a Ensure obsolete peer are removed (peer-reconciler job).
			//     Let's add an obsolete peer to the wireguard Device (but not to the agent),
			//     then trigger the node discovery and ensure the peer is removed from the device.
			dev, err := wgAgent.wgClient.Device(types.IfaceName)
			require.NoError(t, err)
			require.Empty(t, dev.Peers)

			// 6.b Inject the obsolete peer.
			cfg := wgtypes.Config{
				PrivateKey:   nil,
				ListenPort:   nil,
				FirewallMark: nil,
				ReplacePeers: false,
				Peers: []wgtypes.PeerConfig{
					{
						AllowedIPs: []net.IPNet{{IP: k8s2NodeIPv4, Mask: net.IPv4Mask(255, 255, 255, 255)}},
					},
				},
			}
			require.NoError(t, wgAgent.wgClient.ConfigureDevice(types.IfaceName, cfg))

			// 6.c Ensure the injection was successful.
			dev, err = wgAgent.wgClient.Device(types.IfaceName)
			require.NoError(t, err)
			require.Len(t, dev.Peers, 1)

			// 6.d Close CacheStatus to unlock wait from the [*Agent.peerGarbageCollector].
			close(cacheStatus)

			// 6.e TriggerLabelInjection to unlock WaitForRevision from the [*Agent.peerGarbageCollector].
			ipCache.TriggerLabelInjection()

			// 6.f Start node discovery.
			nodeDiscovery.StartDiscovery(ctx)

			// 6.g Ensure the obsolete peer has been removed.
			require.EventuallyWithT(t, func(c *assert.CollectT) {
				dev, err = wgAgent.wgClient.Device(types.IfaceName)
				require.NoError(c, err)
				assert.Empty(c, dev.Peers)
			}, TestTimeout, 50*time.Millisecond)

			// 7.a Ensure the agent subscribed to node events (nodemanager-subscribe job).
			//     Let's upsert a new node, and ensure the agent maps contain the new peer.
			manager.NodeUpdated(nodeTypes.Node{
				Name: k8s2NodeName,
				IPAddresses: []nodeTypes.Address{
					{
						Type: addressing.NodeInternalIP,
						IP:   k8s2NodeIPv4,
					},
				},
				Source:          source.Unspec,
				WireguardPubKey: wgAgent.privKey.String(),
			})

			// 7.b Ensure the agent has stored a peer configuration for the new node.
			require.EventuallyWithT(t, func(c *assert.CollectT) {
				assert.Contains(c, wgAgent.nodeNameByNodeIP, k8s2NodeIPv4.String())
				assert.Contains(c, wgAgent.peerByNodeName, k8s2NodeName)
			}, TestTimeout, 50*time.Millisecond)

			// 8.a Ensure the agent subscribed to IPCache events (ipcache-listener job).
			//     Let's upsert a new identity, and ensure the agent contains it as allowedIP.
			ipCache.Upsert(pod2IPv4Str, k8s2NodeIPv4, 0, nil, ipcache.Identity{ID: 1, Source: source.Kubernetes})

			// 8.b Ensure the agent has the identity in the peer allowedIPs.
			require.EventuallyWithT(t, func(c *assert.CollectT) {
				assert.Contains(c, wgAgent.peerByNodeName, k8s2NodeName)
				assert.Truef(c, func() bool {
					for _, n := range wgAgent.peerByNodeName[k8s2NodeName].allowedIPs {
						if n.Contains(pod2IPv4.IP) {
							return true
						}
					}
					return false
				}(), "Expected allowed IP %v", pod2IPv4.String())
			}, TestTimeout, 50*time.Millisecond)

			// 9. Stop the hive.
			require.NoError(t, hive.Stop(log, ctx))

			// 10. Ensure the link cilium_wg0 is not deleted.
			_, err = safenetlink.LinkByName(types.IfaceName)
			require.NoError(t, err)

			return nil
		})
	})

	t.Run("WireguardDisabled", func(t *testing.T) {
		ns.Do(func() error {
			// 0. Create link cilium_wg0 in case no leftover from previous test.
			netlink.LinkAdd(&netlink.Wireguard{
				LinkAttrs: netlink.LinkAttrs{
					Name: types.IfaceName,
				},
			})

			// 1. Ensure the link cilium_wg0 exists.
			_, err := safenetlink.LinkByName(types.IfaceName)
			require.NoError(t, err)

			// 2. Create a hive with WireGuard disabled.
			hive := getHive(false)

			// 3. Start the hive.
			require.NoError(t, hive.Start(log, ctx))

			// 4. Ensure the wireguard Agent is disabled.
			require.False(t, wgAgent.Enabled())

			// 5. Ensure the link is deleted.
			_, err = safenetlink.LinkByName(types.IfaceName)
			require.Error(t, err)
			require.ErrorAs(t, err, &netlink.LinkNotFoundError{})

			// 6. Stop the hive.
			require.NoError(t, hive.Stop(log, ctx))

			return nil
		})
	})
}
