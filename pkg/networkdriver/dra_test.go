// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package networkdriver

import (
	"context"
	"encoding/json"
	"net/netip"
	"testing"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/hivetest"
	"github.com/cilium/statedb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	resourceapi "k8s.io/api/resource/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	kubetypes "k8s.io/apimachinery/pkg/types"
	"k8s.io/dynamic-resource-allocation/kubeletplugin"

	"github.com/cilium/cilium/daemon/k8s"
	operatoripam "github.com/cilium/cilium/operator/pkg/networkdriver/ipam"
	"github.com/cilium/cilium/pkg/hive"
	iputil "github.com/cilium/cilium/pkg/ip"
	"github.com/cilium/cilium/pkg/ipam"
	ipamtypes "github.com/cilium/cilium/pkg/ipam/types"
	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client/testutils"
	"github.com/cilium/cilium/pkg/k8s/resource"
	"github.com/cilium/cilium/pkg/networkdriver/config"
	"github.com/cilium/cilium/pkg/networkdriver/dummy"
	networkdriverIPAM "github.com/cilium/cilium/pkg/networkdriver/ipam"
	"github.com/cilium/cilium/pkg/networkdriver/types"
	nodetypes "github.com/cilium/cilium/pkg/node/types"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/time"
)

// TestSerializeDevice round-trips devices through serializeDevice /
// deserializeDevice and verifies the fields survive.
func TestSerializeDevice(t *testing.T) {
	t.Run("mock device round-trip", func(t *testing.T) {
		dev := &trackedDevice{name: "eth0"}
		cfg := types.DeviceConfig{PodIfName: "eth0-pod"}
		a := allocation{Device: dev, Config: cfg, Manager: types.DeviceManagerTypeMock}

		raw, err := serializeDevice(a)
		require.NoError(t, err)

		mgr, devRaw, gotCfg, err := deserializeDevice(raw)
		require.NoError(t, err)
		require.Equal(t, types.DeviceManagerTypeMock, mgr)
		require.Equal(t, cfg.PodIfName, gotCfg.PodIfName)
		require.NotEmpty(t, devRaw)
	})

	t.Run("dummy device round-trip", func(t *testing.T) {
		dev := &dummy.DummyDevice{Name: "dummy0", HWAddr: "aa:bb:cc:dd:ee:ff", MTU: 1500}
		cfg := types.DeviceConfig{PodIfName: "eth-pod"}
		a := allocation{Device: dev, Config: cfg, Manager: types.DeviceManagerTypeDummy}

		raw, err := serializeDevice(a)
		require.NoError(t, err)

		mgr, devRaw, gotCfg, err := deserializeDevice(raw)
		require.NoError(t, err)
		require.Equal(t, types.DeviceManagerTypeDummy, mgr)
		require.Equal(t, cfg.PodIfName, gotCfg.PodIfName)
		require.NotEmpty(t, devRaw)

		// Restore from the raw bytes using DummyManager.
		dummyMgr, err := newDummyManager(t)
		require.NoError(t, err)
		restored, err := dummyMgr.RestoreDevice(devRaw)
		require.NoError(t, err)
		require.Equal(t, dev.IfName(), restored.IfName())
	})
}

func TestBuildDeviceStatus(t *testing.T) {
	claim := &resourceapi.ResourceClaim{
		ObjectMeta: metav1.ObjectMeta{Name: "claim", Namespace: "default"},
	}
	result := resourceapi.DeviceRequestAllocationResult{
		Pool:   "pool",
		Device: "device",
	}
	a := allocation{
		Device:  &trackedDevice{name: "eth0"},
		Manager: types.DeviceManagerTypeMock,
		Config: types.DeviceConfig{
			IPv4Addr: netip.MustParsePrefix("10.0.0.1/32"),
			IPv6Addr: netip.MustParsePrefix("fd00::1/128"),
		},
	}

	tests := []struct {
		name        string
		ipv4Enabled bool
		ipv6Enabled bool
		wantIPs     []string
	}{
		{
			name:        "ipv4 only",
			ipv4Enabled: true,
			wantIPs:     []string{"10.0.0.1/32"},
		},
		{
			name:        "ipv6 only",
			ipv6Enabled: true,
			wantIPs:     []string{"fd00::1/128"},
		},
		{
			name:        "dual stack",
			ipv4Enabled: true,
			ipv6Enabled: true,
			wantIPs:     []string{"10.0.0.1/32", "fd00::1/128"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			driver := &Driver{
				config: &v2alpha1.CiliumNetworkDriverNodeConfigSpec{
					DriverName: "testdriver",
				},
				ipv4Enabled: tt.ipv4Enabled,
				ipv6Enabled: tt.ipv6Enabled,
			}

			status, err := driver.buildDeviceStatus(claim, result, a)
			require.NoError(t, err)
			require.NotNil(t, status.NetworkData)
			require.ElementsMatch(t, tt.wantIPs, status.NetworkData.IPs)
		})
	}
}

func TestDeviceClaimConfigs(t *testing.T) {
	tlog := hivetest.Logger(t)
	driver := &Driver{
		logger: tlog,
	}

	t.Run("invalid JSON", func(t *testing.T) {
		claim := &resourceapi.ResourceClaim{
			Status: resourceapi.ResourceClaimStatus{
				Allocation: &resourceapi.AllocationResult{
					Devices: resourceapi.DeviceAllocationResult{
						Config: []resourceapi.DeviceAllocationConfiguration{
							{
								Requests: []string{"req"},
								DeviceConfiguration: resourceapi.DeviceConfiguration{
									Opaque: &resourceapi.OpaqueDeviceConfiguration{
										Parameters: runtime.RawExtension{Raw: []byte("not-json")},
									},
								},
							},
						},
					},
				},
			},
		}
		_, err := driver.deviceClaimConfigs(t.Context(), claim)
		require.Error(t, err)
	})

	t.Run("empty config", func(t *testing.T) {
		claim := &resourceapi.ResourceClaim{
			Status: resourceapi.ResourceClaimStatus{
				Allocation: &resourceapi.AllocationResult{
					Devices: resourceapi.DeviceAllocationResult{
						Results: []resourceapi.DeviceRequestAllocationResult{
							{
								Request: "req",
								Driver:  "testdriver",
								Pool:    "testpool",
								Device:  "mydevice",
							},
						},
					},
				},
			},
		}
		_, err := driver.deviceClaimConfigs(t.Context(), claim)
		require.NoError(t, err)
	})

	t.Run("wrong reservedFor length", func(t *testing.T) {
		for _, tc := range []struct {
			name        string
			reservedFor []resourceapi.ResourceClaimConsumerReference
		}{
			{"zero entries", nil},
			{"two entries", []resourceapi.ResourceClaimConsumerReference{{Resource: "pods"}, {Resource: "pods"}}},
		} {
			t.Run(tc.name, func(t *testing.T) {
				claim := &resourceapi.ResourceClaim{
					Status: resourceapi.ResourceClaimStatus{
						ReservedFor: tc.reservedFor,
						Allocation:  &resourceapi.AllocationResult{},
					},
				}
				res := driver.prepareResourceClaim(t.Context(), claim)
				require.Error(t, res.Err)
				require.ErrorIs(t, res.Err, errUnexpectedInput)
			})
		}
	})
}

// TestPrepareResourceClaim covers end-to-end paths through prepareResourceClaim.
func TestPrepareResourceClaim(t *testing.T) {
	tlog := hivetest.Logger(t)

	t.Run("plain device succeeds", func(t *testing.T) {
		var pods resource.Resource[*corev1.Pod]
		var cs *k8sClient.FakeClientset

		h := hive.New(
			k8sClient.FakeClientCell(),
			k8s.ResourcesCell,
			cell.Provide(
				podResource,
				func() *option.DaemonConfig {
					return &option.DaemonConfig{
						EnableIPv4: true,
						EnableIPv6: true,
					}
				},
			),
			cell.Invoke(func(c *k8sClient.FakeClientset, p resource.Resource[*corev1.Pod]) {
				cs = c
				pods = p
			}),
		)

		hive.AddConfigOverride(
			h,
			func(cfg *config.Config) {
				cfg.Enabled = true
			})

		require.NoError(t, h.Start(tlog, t.Context()))
		t.Cleanup(func() { h.Stop(tlog, context.Background()) })

		require.NotNil(t, pods, "pod resource must be wired by hive")

		db := statedb.New()
		deviceTable, err := newDeviceTable(db)
		require.NoError(t, err)
		allocationTable, err := newAllocationTable(db)
		require.NoError(t, err)

		dev := &trackedDevice{name: "mydevice"}
		wtxn := db.WriteTxn(deviceTable)
		deviceTable.Insert(wtxn, &DRADevice{
			Name:    dev.IfName(),
			Manager: types.DeviceManagerTypeMock,
			Dev:     dev,
		})
		wtxn.Commit()

		driver := &Driver{
			logger:     tlog,
			kubeClient: cs,
			pods:       pods,
			config: &v2alpha1.CiliumNetworkDriverNodeConfigSpec{
				DriverName: "testdriver",
			},
			deviceManagers: map[types.DeviceManagerType]types.DeviceManager{
				types.DeviceManagerTypeMock: &mockDeviceManager{devices: []types.Device{dev}},
			},
			db:              db,
			deviceTable:     deviceTable,
			allocationTable: allocationTable,
		}

		claim := &resourceapi.ResourceClaim{
			ObjectMeta: metav1.ObjectMeta{
				Name:      prepTestClaimName,
				Namespace: prepTestClaimNS,
				UID:       prepTestClaimUID,
			},
			Status: resourceapi.ResourceClaimStatus{
				ReservedFor: []resourceapi.ResourceClaimConsumerReference{{Resource: "pods", UID: prepTestPodUID}},
				Allocation: &resourceapi.AllocationResult{
					Devices: resourceapi.DeviceAllocationResult{
						Results: []resourceapi.DeviceRequestAllocationResult{
							{
								Request: prepTestRequest,
								Driver:  "testdriver",
								Pool:    prepTestPool,
								Device:  "mydevice",
							},
						},
					},
				},
			},
		}
		createPrepClaim(t, cs, claim)

		res := driver.prepareResourceClaim(t.Context(), claim)
		require.NoError(t, res.Err)
	})

	t.Run("already allocated same claim is idempotent", func(t *testing.T) {
		cs, _ := k8sClient.NewFakeClientset(tlog)

		podUID := kubetypes.UID("existing-pod-uid")
		claimUID := kubetypes.UID("existing-claim-uid")

		driver := buildPrepDriver(t, cs)
		// Pre-populate statedb to simulate an already-prepared claim.
		wtxn := driver.db.WriteTxn(driver.allocationTable)
		driver.allocationTable.Insert(wtxn, &DRAAllocation{
			DeviceName:     "existing-device",
			Pool:           prepTestPool,
			Manager:        types.DeviceManagerTypeMock,
			PreparedDevice: &trackedDevice{name: "existing-device"},
			PodUID:         podUID,
			ClaimUID:       claimUID,
		})
		wtxn.Commit()

		claim := &resourceapi.ResourceClaim{
			ObjectMeta: metav1.ObjectMeta{UID: claimUID},
			Status: resourceapi.ResourceClaimStatus{
				ReservedFor: []resourceapi.ResourceClaimConsumerReference{
					{Resource: "pods", UID: podUID},
				},
				Allocation: &resourceapi.AllocationResult{},
			},
		}
		res := driver.prepareResourceClaim(t.Context(), claim)
		require.NoError(t, res.Err)
	})
}

// newDummyManager returns a DummyManager with count=2 for use in tests.
func newDummyManager(t *testing.T) (*dummy.DummyManager, error) {
	t.Helper()
	return dummy.NewManager(hivetest.Logger(t), &v2alpha1.DummyDeviceManagerConfig{Count: 2})
}

func TestNetworkDriverIPAM(t *testing.T) {
	tlog := hivetest.Logger(t)

	const (
		driverName = prepTestDriverName
		devicePool = prepTestPool
		request    = prepTestRequest
		device     = prepTestDev0

		claimName      = prepTestClaimName
		claimNamespace = prepTestClaimNS
	)

	claimUID := prepTestClaimUID
	podUID := prepTestPodUID

	ipv4 := netip.MustParsePrefix("10.30.0.1/32")
	ipv6 := netip.MustParsePrefix("fd00:300:1::1/128")

	rawParam, err := json.Marshal(map[string]string{
		"ipv4Addr": ipv4.String(),
		"ipv6Addr": ipv6.String(),
	})
	require.NoError(t, err)

	claim := &resourceapi.ResourceClaim{
		ObjectMeta: metav1.ObjectMeta{
			Name:      claimName,
			Namespace: claimNamespace,
			UID:       claimUID,
		},
		Status: resourceapi.ResourceClaimStatus{
			Allocation: &resourceapi.AllocationResult{
				Devices: resourceapi.DeviceAllocationResult{
					Config: []resourceapi.DeviceAllocationConfiguration{
						{
							Source:   resourceapi.AllocationConfigSourceClaim,
							Requests: []string{request},
							DeviceConfiguration: resourceapi.DeviceConfiguration{
								Opaque: &resourceapi.OpaqueDeviceConfiguration{
									Driver: driverName,
									Parameters: runtime.RawExtension{
										Raw: rawParam,
									},
								},
							},
						},
					},
					Results: []resourceapi.DeviceRequestAllocationResult{
						{
							Device:  device,
							Driver:  driverName,
							Pool:    devicePool,
							Request: request,
						},
					},
				},
			},
			ReservedFor: []resourceapi.ResourceClaimConsumerReference{
				{
					Resource: "pods",
					Name:     prepTestPodName,
					UID:      podUID,
				},
			},
		},
	}

	cs, _ := k8sClient.NewFakeClientset(tlog)
	createPrepClaim(t, cs, claim)

	dev := &trackedDevice{name: device}
	driver := buildPrepDriver(t, cs, dev)
	driver.ipv4Enabled = true
	driver.ipv6Enabled = true

	// Prepare the claim.
	results, err := driver.PrepareResourceClaims(t.Context(), []*resourceapi.ResourceClaim{claim})
	require.NoError(t, err)
	assert.Contains(t, results, claimUID)
	assert.NoError(t, results[claimUID].Err)

	// Get the claim from the cluster.
	updatedClaim, err := cs.KubernetesFakeClientset.ResourceV1().
		ResourceClaims(claimNamespace).
		Get(t.Context(), claimName, metav1.GetOptions{})
	require.NoError(t, err)

	// Check the updated claim's status.
	require.Len(t, updatedClaim.Status.Devices, 1)
	status := updatedClaim.Status.Devices[0]
	require.Equal(t, driverName, status.Driver)
	require.Equal(t, devicePool, status.Pool)
	require.Equal(t, device, status.Device)
	require.Len(t, status.Conditions, 1)
	require.Equal(t, string(corev1.PodReady), status.Conditions[0].Type)
	require.Equal(t, metav1.ConditionTrue, status.Conditions[0].Status)
	require.NotNil(t, status.NetworkData)
	require.Equal(t, device, status.NetworkData.InterfaceName)
	require.ElementsMatch(t, []string{ipv4.String(), ipv6.String()}, status.NetworkData.IPs)

	_, _, cfg, err := deserializeDevice(status.Data.Raw)
	require.NoError(t, err)
	require.Empty(t, cfg.IPPool)
	require.Equal(t, ipv4, cfg.IPv4Addr)
	require.Equal(t, ipv6, cfg.IPv6Addr)

	// Check the allocated rows for the claim.
	rows := allocatedRowsForClaim(t, driver, claimUID)
	require.Len(t, rows, 1)
	require.Equal(t, device, rows[0].DeviceName)
	require.Equal(t, ipv4, rows[0].Config.IPv4Addr)
	require.Equal(t, ipv6, rows[0].Config.IPv6Addr)
	require.Equal(t, int32(1), dev.setupCalls.Load())

	releaseResults, err := driver.UnprepareResourceClaims(t.Context(), []kubeletplugin.NamespacedObject{
		namedObject(claimNamespace, claimName, claimUID),
	})
	require.NoError(t, err)
	require.NoError(t, releaseResults[claimUID])
	require.Equal(t, int32(1), dev.freeCalls.Load())
	require.Empty(t, allocatedRowsForClaim(t, driver, claimUID))
}

func TestNetworkDriverIPAMPool(t *testing.T) {
	tlog := hivetest.Logger(t)

	const (
		localNodeName = "test-local-node"
		ipPoolName    = "test-ip-pool"
		ipv4CIDR      = "10.10.0.0/16"
		ipv6CIDR      = "fd00:200:1::/48"
	)

	rawParam, err := json.Marshal(map[string]string{"ipPool": ipPoolName})
	require.NoError(t, err)

	claim := &resourceapi.ResourceClaim{
		ObjectMeta: metav1.ObjectMeta{
			Name:      prepTestClaimName,
			Namespace: prepTestClaimNS,
			UID:       prepTestClaimUID,
		},
		Status: resourceapi.ResourceClaimStatus{
			Allocation: &resourceapi.AllocationResult{
				Devices: resourceapi.DeviceAllocationResult{
					Config: []resourceapi.DeviceAllocationConfiguration{
						{
							Source:   resourceapi.AllocationConfigSourceClaim,
							Requests: []string{prepTestRequest},
							DeviceConfiguration: resourceapi.DeviceConfiguration{
								Opaque: &resourceapi.OpaqueDeviceConfiguration{
									Driver:     prepTestDriverName,
									Parameters: runtime.RawExtension{Raw: rawParam},
								},
							},
						},
					},
					Results: []resourceapi.DeviceRequestAllocationResult{
						{
							Device:  prepTestDev0,
							Driver:  prepTestDriverName,
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
		ObjectMeta: metav1.ObjectMeta{Name: ipPoolName},
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
				ObjectMeta: metav1.ObjectMeta{Name: localNodeName},
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
	require.NotNil(t, mgr)
	require.NotNil(t, cs)

	createPrepClaim(t, cs, claim)

	dev := &trackedDevice{name: prepTestDev0}
	driver := buildPrepDriver(t, cs, dev)
	driver.multiPoolMgr = mgr
	driver.ipv4Enabled = true
	driver.ipv6Enabled = true
	driver.multiPoolMgr.RestoreFinished(ipam.IPv4)
	driver.multiPoolMgr.RestoreFinished(ipam.IPv6)

	res := prepOne(t, driver, claim)
	require.NoError(t, res.Err)

	updatedClaim, err := cs.KubernetesFakeClientset.ResourceV1().ResourceClaims(prepTestClaimNS).Get(t.Context(), prepTestClaimName, metav1.GetOptions{})
	require.NoError(t, err)
	require.Len(t, updatedClaim.Status.Devices, 1)

	status := updatedClaim.Status.Devices[0]
	require.Equal(t, prepTestDriverName, status.Driver)
	require.Equal(t, prepTestPool, status.Pool)
	require.Equal(t, prepTestDev0, status.Device)
	require.Len(t, status.Conditions, 1)
	require.Equal(t, string(corev1.PodReady), status.Conditions[0].Type)
	require.Equal(t, metav1.ConditionTrue, status.Conditions[0].Status)
	require.NotNil(t, status.NetworkData)
	require.Equal(t, prepTestDev0, status.NetworkData.InterfaceName)

	curLocalNode, err := cs.CiliumFakeClientset.CiliumV2().CiliumNodes().Get(t.Context(), localNodeName, metav1.GetOptions{})
	require.NoError(t, err)
	require.Equal(t, []ipamtypes.IPAMPoolRequest{
		{
			Pool: ipPoolName,
			Needed: ipamtypes.IPAMPoolDemand{
				IPv4Addrs: 1,
				IPv6Addrs: 1,
			},
		},
	}, curLocalNode.Spec.IPAM.ResourcePools.Requested)
	require.Len(t, curLocalNode.Spec.IPAM.ResourcePools.Allocated, 1)
	require.Equal(t, ipPoolName, curLocalNode.Spec.IPAM.ResourcePools.Allocated[0].Pool)

	v4PoolCIDR := netip.MustParsePrefix(ipv4CIDR)
	v6PoolCIDR := netip.MustParsePrefix(ipv6CIDR)
	var v4NodeCIDR, v6NodeCIDR netip.Prefix
	for _, cidr := range curLocalNode.Spec.IPAM.ResourcePools.Allocated[0].CIDRs {
		prefix := cidr.Prefix
		if prefix.Addr().Is6() {
			v6NodeCIDR = prefix
		} else {
			v4NodeCIDR = prefix
		}
	}

	_, _, cfg, err := deserializeDevice(status.Data.Raw)
	require.NoError(t, err)
	require.Equal(t, ipPoolName, cfg.IPPool)
	require.Equal(t, 32, cfg.IPv4Addr.Bits())
	require.True(t, v4PoolCIDR.Contains(cfg.IPv4Addr.Addr()))
	require.True(t, v4NodeCIDR.Contains(cfg.IPv4Addr.Addr()))
	require.Equal(t, 128, cfg.IPv6Addr.Bits())
	require.True(t, v6PoolCIDR.Contains(cfg.IPv6Addr.Addr()))
	require.True(t, v6NodeCIDR.Contains(cfg.IPv6Addr.Addr()))
	require.ElementsMatch(t, []string{cfg.IPv4Addr.String(), cfg.IPv6Addr.String()}, status.NetworkData.IPs)

	rows := allocatedRowsForClaim(t, driver, prepTestClaimUID)
	require.Len(t, rows, 1)
	require.Equal(t, ipPoolName, rows[0].Config.IPPool)
	require.Equal(t, cfg.IPv4Addr, rows[0].Config.IPv4Addr)
	require.Equal(t, cfg.IPv6Addr, rows[0].Config.IPv6Addr)
	require.Equal(t, int32(1), dev.setupCalls.Load())

	releaseResults, err := driver.UnprepareResourceClaims(t.Context(), []kubeletplugin.NamespacedObject{
		namedObject(prepTestClaimNS, prepTestClaimName, prepTestClaimUID),
	})
	require.NoError(t, err)
	require.NoError(t, releaseResults[prepTestClaimUID])
	require.Equal(t, int32(1), dev.freeCalls.Load())
	require.Empty(t, allocatedRowsForClaim(t, driver, prepTestClaimUID))

	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		localNode, err := cs.CiliumFakeClientset.CiliumV2().CiliumNodes().Get(t.Context(), localNodeName, metav1.GetOptions{})
		assert.NoError(c, err)
		assert.Empty(c, localNode.Spec.IPAM.ResourcePools.Requested)
		assert.Empty(c, localNode.Spec.IPAM.ResourcePools.Allocated)
	}, 10*time.Second, 100*time.Millisecond)
}
