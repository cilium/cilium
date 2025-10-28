// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ipsec

import (
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/hivetest"
	"github.com/cilium/statedb"

	cnicell "github.com/cilium/cilium/daemon/cmd/cni"
	fakecni "github.com/cilium/cilium/daemon/cmd/cni/fake"
	"github.com/cilium/cilium/daemon/k8s"
	"github.com/cilium/cilium/pkg/clustermesh"
	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	fakeTypes "github.com/cilium/cilium/pkg/datapath/fake/types"
	"github.com/cilium/cilium/pkg/datapath/iptables/ipset"
	"github.com/cilium/cilium/pkg/datapath/linux/sysctl"
	"github.com/cilium/cilium/pkg/datapath/tables"
	"github.com/cilium/cilium/pkg/datapath/tunnel"
	"github.com/cilium/cilium/pkg/datapath/types"
	"github.com/cilium/cilium/pkg/dial"
	"github.com/cilium/cilium/pkg/endpoint/regeneration"
	envoy "github.com/cilium/cilium/pkg/envoy/config"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/ipcache"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client/testutils"
	k8sSynced "github.com/cilium/cilium/pkg/k8s/synced"
	"github.com/cilium/cilium/pkg/k8s/watchers"
	"github.com/cilium/cilium/pkg/kvstore"
	"github.com/cilium/cilium/pkg/kvstore/store"
	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/loadbalancer/writer"
	"github.com/cilium/cilium/pkg/maps/encrypt"
	"github.com/cilium/cilium/pkg/mtu"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/node/addressing"
	nodeManager "github.com/cilium/cilium/pkg/node/manager"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
	"github.com/cilium/cilium/pkg/nodediscovery"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/source"
	"github.com/cilium/cilium/pkg/testutils"
	"github.com/cilium/cilium/pkg/testutils/netns"
	"github.com/cilium/cilium/pkg/time"
	wgTypes "github.com/cilium/cilium/pkg/wireguard/types"
)

var (
	TestTimeout  = 5 * time.Second
	k8s1NodeIPv4 = net.ParseIP("192.168.60.11")
	k8s1NodeName = "k8s1"
)

// paramsOut holds the output parameters needed for running cells in the test.
type paramsOut struct {
	cell.Out

	IPSecConfig           Config
	WireguardConfig       wgTypes.WireguardConfig
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
	NodeHandler           types.NodeHandler
	SecretSyncConfig      envoy.SecretSyncConfig
}

func TestPrivileged_TestIPSecCell(t *testing.T) {
	// Needed to create the test namespace, bpf maps and XFRM.
	testutils.PrivilegedTest(t)

	// Create a temporary directory, used also by the agent for the ipsec key.
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
		ipsecAgent  *Agent
		nodeStore   *node.LocalNodeStore
		mtuConfig   mtu.MTU
		encryptMap  encrypt.EncryptMap
		nodeHandler types.NodeHandler

		ctx = t.Context()
		ns  = netns.NewNetNS(t)
		log = hivetest.Logger(t, hivetest.LogLevel(slog.LevelError))

		validKey        = []byte("4 rfc4106(gcm(aes)) 44434241343332312423222114131211f4f3f2f1 128\n")
		anotherValidKey = []byte("5 rfc4106(gcm(aes)) 44434241343332312423222114131211f4f3f2f1 128\n")
		invalidKey      = []byte("6 test abcdefghijklmnopqrstuvwzyzABCDEF test abcdefghijklmnopqrstuvwzyzABCDEF\n")
		keyFile         = filepath.Join(testRunDir, "cilium_ipsec.key")

		zeroKey = encrypt.EncryptKey{Key: 0}
	)

	// getHive returns a new hive with IPSec enabled/disabled.
	getHive := func(ipsecEnabled bool) *hive.Hive {
		return hive.New(
			mtu.Cell,
			encrypt.Cell,
			nodeManager.Cell,
			nodediscovery.Cell,
			source.Cell,
			watchers.Cell,
			dial.ServiceResolverCell,
			clustermesh.Cell,
			writer.Cell,
			ipset.Cell,
			k8s.ResourcesCell,
			node.LocalNodeStoreTestCell,
			k8sClient.FakeClientCell(),
			kvstore.Cell(kvstore.DisabledBackendName),

			cell.Provide(
				newIPsecAgent,
				newIPsecConfig,

				regeneration.NewFence,
				tables.NewDeviceTable,
				tables.NewNodeAddressTable,
				ipcache.NewLocalIPIdentityWatcher,
				ipcache.NewIPIdentitySynchronizer,
				statedb.RWTable[*tables.Device].ToTable,
				statedb.RWTable[tables.NodeAddress].ToTable,

				func() paramsOut {
					return paramsOut{
						IPSecConfig: Config{
							UserConfig: UserConfig{
								EnableConfig: EnableConfig{
									EnableIPsec: ipsecEnabled,
								},
								EnableIPsecKeyWatcher:                    true,
								EnableIPsecXfrmStateCaching:              true,
								UseCiliumInternalIPForIPsec:              false,
								DNSProxyInsecureSkipTransparentModeCheck: false,
								IPsecKeyFile:                             keyFile,
								IPsecKeyRotationDuration:                 1 * time.Second,
							},
							EncryptNode: false,
						},
						WireguardConfig:  fakeTypes.WireguardConfig{},
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
							Context: ctx,
							Logger:  hivetest.Logger(t),
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
						NodeHandler:           fakeTypes.NewNodeHandler(),
						SecretSyncConfig:      envoy.SecretSyncConfig{},
					}
				},
			),

			cell.Invoke(
				func(a types.IPsecAgent, s *node.LocalNodeStore, m mtu.MTU, e encrypt.EncryptMap, n types.NodeHandler) {
					ipsecAgent = a.(*Agent)
					nodeStore = s
					mtuConfig = m
					nodeHandler = n
					if a.Enabled() {
						encryptMap = e
					}
				}),
		)
	}

	// Remove pinned encryption map upon finishing.
	t.Cleanup(func() {
		if encryptMap != nil {
			encryptMap.UnpinIfExists()
		}
	})

	t.Run("IPSecEnabled", func(t *testing.T) {
		ns.Do(func() error {
			// 0. Dump a valid IPSec key to file.
			require.NoError(t, os.WriteFile(keyFile, validKey, 0644))

			// 1. Create a hive with IPSec enabled.
			hive := getHive(true)

			// 2. Start the hive.
			require.NoError(t, hive.Start(log, ctx))

			// 3. Ensure the ipsec agent is enabled.
			require.True(t, ipsecAgent.Enabled())

			// 4. Ensure the MTU returns the correct value.
			require.EventuallyWithT(t, func(c *assert.CollectT) {
				overhead := mtu.EncryptionIPsecOverhead + (ipsecAgent.authKeySize - mtu.EncryptionDefaultAuthKeyLength)
				assert.Equal(c, mtuConfig.GetDeviceMTU(), mtuConfig.GetRouteMTU()+overhead)
			}, TestTimeout, 50*time.Millisecond)

			// 5. Ensure local node has been updated.
			localNode, err := nodeStore.Get(ctx)
			require.NoError(t, err)
			assert.Equal(t, localNode.EncryptionKey, ipsecAgent.spi)

			// 6. Ensure encrypt map is updated accordingly.
			v, err := encryptMap.Lookup(zeroKey)
			require.NoError(t, err)
			assert.Equal(t, ipsecAgent.spi, v.KeyID)

			// 6. Start background ipsec jobs.
			require.NoError(t, ipsecAgent.StartBackgroundJobs(nodeHandler))

			// 7. Dump another valid IPSec key to file.
			require.NoError(t, os.WriteFile(keyFile, anotherValidKey, 0644))

			// 8. Ensure the ipsec agent updated the spi accordingly.
			require.EventuallyWithT(t, func(c *assert.CollectT) {
				assert.Equal(c, uint8(5), ipsecAgent.spi)
				v, err := encryptMap.Lookup(zeroKey)
				assert.NoError(c, err)
				assert.Equal(c, ipsecAgent.spi, v.KeyID)
				assert.NotEmpty(c, ipsecAgent.ipSecKeysRemovalTime)
			}, TestTimeout, 50*time.Millisecond)

			// 8. Dump an invalid IPSec key to file.
			require.NoError(t, os.WriteFile(keyFile, invalidKey, 0644))

			// 9. Ensure the ipsec agent rejected the new key.
			require.EventuallyWithT(t, func(c *assert.CollectT) {
				assert.Equal(c, uint8(5), ipsecAgent.spi)
				v, err := encryptMap.Lookup(zeroKey)
				assert.NoError(c, err)
				assert.Equal(c, ipsecAgent.spi, v.KeyID)
			}, TestTimeout, 50*time.Millisecond)

			// 10. Stop the hive.
			require.NoError(t, hive.Stop(log, ctx))

			return nil
		})
	})

	t.Run("IPSecDisabled", func(t *testing.T) {
		ns.Do(func() error {
			// 0. Dump a valid IPSec key to file.
			require.NoError(t, os.WriteFile(keyFile, validKey, 0644))

			// 1. Create a hive with ipsec disabled.
			hive := getHive(false)

			// 2. Start the hive.
			require.NoError(t, hive.Start(log, ctx))

			// 3. Ensure the ipsec Agent is disabled.
			require.False(t, ipsecAgent.Enabled())

			// 4. Ensure the MTU is not changed.
			require.EventuallyWithT(t, func(c *assert.CollectT) {
				assert.Equal(c, mtuConfig.GetDeviceMTU(), mtuConfig.GetRouteMTU())
			}, TestTimeout, 50*time.Millisecond)

			// 5. Ensure local node has not been updated.
			localNode, err := nodeStore.Get(ctx)
			require.NoError(t, err)
			assert.Zero(t, localNode.EncryptionKey)

			// 6. Ensure the ipsec agent did not update the key.
			//    Current key SPI would've been 4, but encryptMap still has 5 from previous test.
			require.EventuallyWithT(t, func(c *assert.CollectT) {
				assert.Equal(c, uint8(0), ipsecAgent.spi)
				v, err := encryptMap.Lookup(zeroKey)
				assert.NoError(c, err)
				assert.NotEqual(c, uint8(4), v.KeyID)
			}, TestTimeout, 50*time.Millisecond)

			// 7. Stop the hive.
			require.NoError(t, hive.Stop(log, ctx))

			return nil
		})
	})
}
