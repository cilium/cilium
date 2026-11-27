// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package networkdriver

import (
	"context"
	"encoding/json"
	"net/netip"
	"testing"

	uhive "github.com/cilium/hive"
	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/hivetest"
	"github.com/cilium/statedb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	resourceapi "k8s.io/api/resource/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"

	"github.com/cilium/cilium/daemon/k8s"
	operatoripam "github.com/cilium/cilium/operator/pkg/networkdriver/ipam"
	"github.com/cilium/cilium/pkg/hive"
	iputil "github.com/cilium/cilium/pkg/ip"
	"github.com/cilium/cilium/pkg/ipam"
	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client/testutils"
	"github.com/cilium/cilium/pkg/networkdriver/config"
	networkdriverIPAM "github.com/cilium/cilium/pkg/networkdriver/ipam"
	"github.com/cilium/cilium/pkg/networkdriver/networkconfig"
	"github.com/cilium/cilium/pkg/networkdriver/types"
	nodetypes "github.com/cilium/cilium/pkg/node/types"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/time"
)

// newRoute creates a new static route. An empty gateway means the route is direct.
func newRoute(destination, gateway string) types.StaticRoute {
	var gw *netip.Addr
	if gateway != "" {
		gw = new(netip.MustParseAddr(gateway))
	}
	return types.StaticRoute{
		Destination: netip.MustParsePrefix(destination),
		Gateway:     gw,
	}
}

func TestApplyNetworkConfig(t *testing.T) {
	dualStackConfig := types.DeviceConfig{
		IPv4Addr: netip.MustParsePrefix("10.20.0.5/32"),
		IPv6Addr: netip.MustParsePrefix("fd00:20::5/128"),
	}

	tests := []struct {
		name       string
		netConf    string
		config     types.DeviceConfig
		wantIPv4   netip.Prefix
		wantIPv6   netip.Prefix
		wantRoutes []types.StaticRoute
		wantErr    string
	}{
		{
			name: "prefix lengths and routes of both families",
			netConf: `{"spec": {
				"ipv4": [{"cidr": "10.20.0.0/16", "prefixLength": 20,
					"routes": [{"destination": "10.40.0.0/16", "gateway": "10.20.0.1"}]}],
				"ipv6": [{"cidr": "fd00:20::/48", "prefixLength": 56,
					"routes": [{"destination": "fd00:30::/48", "gateway": "fd00:20::1"}]}]}}`,
			config:   dualStackConfig,
			wantIPv4: netip.MustParsePrefix("10.20.0.5/20"),
			wantIPv6: netip.MustParsePrefix("fd00:20::5/56"),
			wantRoutes: []types.StaticRoute{
				newRoute("10.40.0.0/16", "10.20.0.1"),
				newRoute("fd00:30::/48", "fd00:20::1"),
			},
		},
		{
			name: "no entry contains the addresses",
			netConf: `{"spec": {
				"ipv4": [{"cidr": "10.99.0.0/16", "prefixLength": 20,
					"routes": [{"destination": "10.40.0.0/16", "gateway": "10.99.0.1"}]}]}}`,
			config:   dualStackConfig,
			wantIPv4: dualStackConfig.IPv4Addr,
			wantIPv6: dualStackConfig.IPv6Addr,
		},
		{
			name: "ipv6 entry without routes keeps the ipv4 routes",
			netConf: `{"spec": {
				"ipv4": [{"cidr": "10.20.0.0/16", "prefixLength": 20,
					"routes": [{"destination": "10.40.0.0/16", "gateway": "10.20.0.1"}]}],
				"ipv6": [{"cidr": "fd00:20::/48", "prefixLength": 56}]}}`,
			config:     dualStackConfig,
			wantIPv4:   netip.MustParsePrefix("10.20.0.5/20"),
			wantIPv6:   netip.MustParsePrefix("fd00:20::5/56"),
			wantRoutes: []types.StaticRoute{newRoute("10.40.0.0/16", "10.20.0.1")},
		},
		{
			name: "route without gateway",
			netConf: `{"spec": {
				"ipv4": [{"cidr": "10.20.0.0/16", "prefixLength": 20,
					"routes": [{"destination": "10.40.0.0/16"}]}]}}`,
			config:     types.DeviceConfig{IPv4Addr: dualStackConfig.IPv4Addr},
			wantIPv4:   netip.MustParsePrefix("10.20.0.5/20"),
			wantRoutes: []types.StaticRoute{newRoute("10.40.0.0/16", "")},
		},
		{
			name: "prefix length not valid for the address family",
			netConf: `{"spec": {
				"ipv4": [{"cidr": "10.20.0.0/16", "prefixLength": 40}]}}`,
			config:   dualStackConfig,
			wantIPv4: dualStackConfig.IPv4Addr,
			wantIPv6: dualStackConfig.IPv6Addr,
			wantErr:  "invalid entry prefix length 40",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var netConf networkconfig.LocalResourceNetworkConfig
			require.NoError(t, json.Unmarshal([]byte(tc.netConf), &netConf))
			alloc := allocation{Config: tc.config}

			err := applyNetworkConfig(&netConf, &alloc)
			if tc.wantErr != "" {
				require.ErrorContains(t, err, tc.wantErr)
			} else {
				require.NoError(t, err)
			}

			assert.Equal(t, tc.wantIPv4, alloc.Config.IPv4Addr)
			assert.Equal(t, tc.wantIPv6, alloc.Config.IPv6Addr)
			assert.Equal(t, tc.wantRoutes, alloc.StaticRoutes)
		})
	}
}

func TestNetworkDriverIPAMPoolInvalidNetworkConfig(t *testing.T) {
	tlog := hivetest.Logger(t)

	const (
		localNodeName     = "test-local-node"
		ipPoolName        = "test-ip-pool"
		networkConfigName = "test-network-config"
		ipv4CIDR          = "10.10.0.0/16"
		ipv6CIDR          = "fd00:200:1::/48"
	)

	rawParam, err := json.Marshal(map[string]string{
		"ipPool":        ipPoolName,
		"networkConfig": networkConfigName,
	})
	require.NoError(t, err)

	claim := &resourceapi.ResourceClaim{
		Name:      prepTestClaimName,
		Namespace: prepTestClaimNS,
		UID:       prepTestClaimUID,
		Status: resourceapi.ResourceClaimStatus{
			Allocation: &resourceapi.AllocationResult{
				Devices: resourceapi.DeviceAllocationResult{
					Config: []resourceapi.DeviceAllocationConfiguration{
						{
							Source:   resourceapi.AllocationConfigSourceClaim,
							Requests: []string{prepTestRequest},
							Opaque: &resourceapi.OpaqueDeviceConfiguration{
								Driver:     networkDriverName,
								Parameters: runtime.RawExtension{Raw: rawParam},
							},
						},
					},
					Results: []resourceapi.DeviceRequestAllocationResult{
						{
							Device:  prepTestDev0,
							Driver:  networkDriverName,
							Pool:    prepTestPool,
							Request: prepTestRequest,
						},
					},
				},
			},
			ReservedFor: []resourceapi.ResourceClaimConsumerReference{
				{Resource: "pods", Name: prepTestPodName, UID: prepTestPodUID},
			},
		},
	}

	resourceIPPool := &v2alpha1.CiliumResourceIPPool{
		Name: ipPoolName,
		Spec: v2alpha1.ResourceIPPoolSpec{
			IPv4: &v2.IPv4PoolSpec{
				CIDRs:    []iputil.Prefix{iputil.PrefixFrom(netip.MustParsePrefix(ipv4CIDR))},
				MaskSize: 24,
			},
			IPv6: &v2.IPv6PoolSpec{
				CIDRs:    []iputil.Prefix{iputil.PrefixFrom(netip.MustParsePrefix(ipv6CIDR))},
				MaskSize: 64,
			},
		},
	}

	var (
		mgr *ipam.MultiPoolManager
		cs  *k8sClient.FakeClientset
	)

	daemonCfg := &option.DaemonConfig{
		EnableIPv4:               true,
		EnableIPv6:               true,
		IPAMCiliumNodeUpdateRate: time.Nanosecond,
	}

	h := hive.New(
		k8sClient.FakeClientCell(),
		k8s.ResourcesCell,
		cell.Config(config.DefaultConfig),
		operatoripam.Cell,
		networkdriverIPAM.Cell,
		cell.Provide(func() *option.DaemonConfig { return daemonCfg }),
		cell.Invoke(func(c *k8sClient.FakeClientset) {
			cs = c
			_, err := c.CiliumFakeClientset.CiliumV2alpha1().CiliumResourceIPPools().Create(t.Context(), resourceIPPool, metav1.CreateOptions{})
			require.NoError(t, err)

			nodetypes.SetName(localNodeName)
			_, err = c.CiliumFakeClientset.CiliumV2().CiliumNodes().Create(t.Context(), &v2.CiliumNode{
				Name: localNodeName,
			}, metav1.CreateOptions{})
			require.NoError(t, err)
		}),
		cell.Invoke(func(m *ipam.MultiPoolManager) {
			mgr = m
		}),
	)
	hive.AddConfigOverride(h, func(cfg *config.Config) {
		cfg.Enabled = true
		cfg.IPv4Enabled = true
		cfg.IPv6Enabled = true
	})
	require.NoError(t, h.Start(tlog, t.Context()))
	t.Cleanup(func() { h.Stop(tlog, context.Background()) })

	createPrepClaim(t, cs, claim)

	dev := &trackedDevice{name: prepTestDev0}
	driver := buildPrepDriver(t, cs, dev)
	driver.multiPoolMgr = mgr
	driver.ipv4Enabled = true
	driver.ipv6Enabled = true
	driver.multiPoolMgr.RestoreFinished(ipam.IPv4)
	driver.multiPoolMgr.RestoreFinished(ipam.IPv6)

	var netConf networkconfig.LocalResourceNetworkConfig
	require.NoError(t, json.Unmarshal([]byte(`{"name": "`+networkConfigName+`", "spec": {
		"ipv4": [{"cidr": "`+ipv4CIDR+`", "prefixLength": 40}]}}`), &netConf))
	insertNetworkConfig(t, driver, netConf)

	res := prepOne(t, driver, claim)
	require.ErrorContains(t, res.Err, "invalid entry prefix length 40")
	require.Equal(t, int32(0), dev.setupCalls.Load())
	require.Empty(t, allocatedRowsForClaim(t, driver, prepTestClaimUID))

	// the addresses allocated from the pool before the failure must be released
	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		localNode, err := cs.CiliumFakeClientset.CiliumV2().CiliumNodes().Get(t.Context(), localNodeName, metav1.GetOptions{})
		assert.NoError(c, err)
		assert.Empty(c, localNode.Spec.IPAM.ResourcePools.Requested)
		assert.Empty(c, localNode.Spec.IPAM.ResourcePools.Allocated)
	}, 10*time.Second, 100*time.Millisecond)
}

// insertNetworkConfig creates the network config table in the driver database and adds cfg to it.
func insertNetworkConfig(t *testing.T, driver *Driver, cfg networkconfig.LocalResourceNetworkConfig) {
	t.Helper()

	var table statedb.RWTable[networkconfig.LocalResourceNetworkConfig]
	require.NoError(t, uhive.New(
		cell.Provide(func() *statedb.DB { return driver.db }),
		networkconfig.TableCell,
		cell.Invoke(func(tbl statedb.RWTable[networkconfig.LocalResourceNetworkConfig]) {
			table = tbl
		}),
	).Populate(hivetest.Logger(t)))
	driver.localNetConfs = table

	wtxn := driver.db.WriteTxn(table)
	_, _, err := table.Insert(wtxn, cfg)
	require.NoError(t, err)
	wtxn.Commit()
}
