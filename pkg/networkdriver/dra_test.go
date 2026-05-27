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
	v1 "k8s.io/api/resource/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	kubetypes "k8s.io/apimachinery/pkg/types"
	"k8s.io/dynamic-resource-allocation/kubeletplugin"

	"github.com/cilium/cilium/daemon/k8s"
	operatoripam "github.com/cilium/cilium/operator/pkg/networkdriver/ipam"
	"github.com/cilium/cilium/pkg/annotation"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/ipam"
	ipamtypes "github.com/cilium/cilium/pkg/ipam/types"
	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client/testutils"
	"github.com/cilium/cilium/pkg/k8s/resource"
	"github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/labels"
	slimv1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/k8s/synced"
	"github.com/cilium/cilium/pkg/networkdriver/dummy"
	"github.com/cilium/cilium/pkg/networkdriver/types"
	"github.com/cilium/cilium/pkg/node"
	nodetypes "github.com/cilium/cilium/pkg/node/types"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/promise"
	"github.com/cilium/cilium/pkg/testutils"
	"github.com/cilium/cilium/pkg/time"
)

func TestNetworkDriverIPAM(t *testing.T) {
	t.Cleanup(func() {
		testutils.GoleakVerifyNone(t)
	})

	var (
		daemonCfg = &option.DaemonConfig{
			EnableCiliumNetworkDriver: true,
			EnableIPv4:                true,
			EnableIPv6:                true,
			IPAMCiliumNodeUpdateRate:  time.Nanosecond,
		}

		driverName = "test.cilium.k8s.io"
		devicePool = "test-device-pool"
		request    = "test-request"
		device     = "test-device"

		claimName      = "test-pod-test-4d5bl"
		claimNamespace = "default"
		claimUID       = kubetypes.UID("ba3c7922-9a56-44eb-a96f-84ee8b74dd23")

		claimConsumerResource = "pods"
		ClaimConsumerName     = "test-pod"
		ClaimConsumerUID      = kubetypes.UID("bec9dd67-13f9-4d4b-a3c1-76fc3e485e68")
	)

	var (
		ipv4 = "10.30.0.1/32"
		ipv6 = "fd00:300:1::1/128"
	)

	rawParam, err := json.Marshal(map[string]string{
		"ipv4Addr": ipv4,
		"ipv6Addr": ipv6,
	})
	assert.NoError(t, err)

	claims := []*resourceapi.ResourceClaim{
		{
			ObjectMeta: metav1.ObjectMeta{
				Name:      claimName,
				Namespace: claimNamespace,
				UID:       claimUID,
			},
			Status: v1.ResourceClaimStatus{
				Allocation: &v1.AllocationResult{
					Devices: v1.DeviceAllocationResult{
						Config: []v1.DeviceAllocationConfiguration{
							{
								Source:   v1.AllocationConfigSourceClaim,
								Requests: []string{request},
								DeviceConfiguration: v1.DeviceConfiguration{
									Opaque: &v1.OpaqueDeviceConfiguration{
										Driver: driverName,
										Parameters: runtime.RawExtension{
											Raw: rawParam,
										},
									},
								},
							},
						},
						Results: []v1.DeviceRequestAllocationResult{
							{
								Device:  device,
								Driver:  driverName,
								Pool:    devicePool,
								Request: request,
							},
						},
					},
				},
				ReservedFor: []v1.ResourceClaimConsumerReference{
					{
						Resource: claimConsumerResource,
						Name:     ClaimConsumerName,
						UID:      ClaimConsumerUID,
					},
				},
			},
		},
	}

	var (
		mgr  *ipam.MultiPoolManager
		cs   *k8sClient.FakeClientset
		pods resource.Resource[*corev1.Pod]
	)

	hive := hive.New(
		k8sClient.FakeClientCell(),
		k8s.ResourcesCell,
		cell.Provide(
			podResource,
			func() *option.DaemonConfig {
				return daemonCfg
			},
		),
		resourceIPAM,

		cell.Invoke(func(c *k8sClient.FakeClientset) {
			for i := range len(claims) {
				current, err := c.KubernetesFakeClientset.ResourceV1().ResourceClaims(claims[i].Namespace).Create(t.Context(), claims[i], metav1.CreateOptions{})
				claims[i].SetResourceVersion(current.ResourceVersion)
				assert.NoError(t, err)
			}
		}),
		cell.Invoke(func(m *ipam.MultiPoolManager, c *k8sClient.FakeClientset, p resource.Resource[*corev1.Pod]) {
			mgr = m
			cs = c
			pods = p
		}),
	)

	tlog := hivetest.Logger(t)
	assert.NoError(t, hive.Start(tlog, t.Context()))

	driver := &Driver{
		logger:     tlog,
		kubeClient: cs,
		pods:       pods,
		config: &v2alpha1.CiliumNetworkDriverNodeConfigSpec{
			DriverName: driverName,
		},
		devices: map[types.DeviceManagerType][]types.Device{
			types.DeviceManagerTypeDummy: {
				&dummy.DummyDevice{
					Name: device,
				},
			},
		},
		allocations:  make(map[kubetypes.UID]map[kubetypes.UID][]allocation),
		multiPoolMgr: mgr,
		ipv4Enabled:  daemonCfg.IPv4Enabled(),
		ipv6Enabled:  daemonCfg.IPv6Enabled(),
	}

	results, err := driver.PrepareResourceClaims(t.Context(), claims)
	assert.NoError(t, err)
	assert.Contains(t, results, claimUID)
	assert.NoError(t, results[claimUID].Err)

	claim, err := cs.Clientset.ResourceV1().ResourceClaims(claimNamespace).Get(t.Context(), claimName, metav1.GetOptions{})
	assert.NoError(t, err)

	assert.Len(t, claim.Status.Devices, 1)
	assert.Equal(t, driverName, claim.Status.Devices[0].Driver)
	assert.Equal(t, devicePool, claim.Status.Devices[0].Pool)
	assert.Equal(t, device, claim.Status.Devices[0].Device)
	assert.Len(t, claim.Status.Devices[0].Conditions, 1)
	assert.Equal(t, "Ready", claim.Status.Devices[0].Conditions[0].Type)
	assert.Equal(t, metav1.ConditionTrue, claim.Status.Devices[0].Conditions[0].Status)

	var alloc allocation
	assert.NoError(t, json.Unmarshal(claim.Status.Devices[0].Data.Raw, &alloc))
	assert.Empty(t, alloc.Config.IPPool)
	assert.Equal(t, netip.MustParsePrefix(ipv4), alloc.Config.IPv4Addr)
	assert.Equal(t, netip.MustParsePrefix(ipv6), alloc.Config.IPv6Addr)

	assert.Equal(t, device, claim.Status.Devices[0].NetworkData.InterfaceName)
	addrs := []string{alloc.Config.IPv4Addr.String(), alloc.Config.IPv6Addr.String()}
	assert.ElementsMatch(t, addrs, claim.Status.Devices[0].NetworkData.IPs)

	claimsToRelease := []kubeletplugin.NamespacedObject{
		{
			NamespacedName: kubetypes.NamespacedName{
				Namespace: claimNamespace,
				Name:      claimName,
			},
			UID: claimUID,
		},
	}

	releaseResults, err := driver.UnprepareResourceClaims(t.Context(), claimsToRelease)
	assert.NoError(t, err)
	assert.Contains(t, releaseResults, claimUID)
	assert.NoError(t, releaseResults[claimUID])

	assert.NoError(t, hive.Stop(tlog, t.Context()))
}

func TestNetworkDriverIPAMPool(t *testing.T) {
	t.Cleanup(func() {
		testutils.GoleakVerifyNone(t)
	})

	var (
		daemonCfg = &option.DaemonConfig{
			EnableCiliumNetworkDriver: true,
			EnableIPv4:                true,
			EnableIPv6:                true,
			IPAMCiliumNodeUpdateRate:  time.Nanosecond,
		}

		localNodeName = "test-local-node"

		driverName = "test.cilium.k8s.io"
		devicePool = "test-device-pool"
		request    = "test-request"
		device     = "test-device"

		claimName      = "test-pod-test-4d5bl"
		claimNamespace = "default"
		claimUID       = kubetypes.UID("ba3c7922-9a56-44eb-a96f-84ee8b74dd23")

		claimConsumerResource = "pods"
		ClaimConsumerName     = "test-pod"
		ClaimConsumerUID      = kubetypes.UID("bec9dd67-13f9-4d4b-a3c1-76fc3e485e68")
	)

	var (
		ipPoolName   = "test-ip-pool"
		ipv4CIDR     = "10.10.0.0/16"
		ipv4MaskSize = 24
		ipv6CIDR     = "fd00:200:1::/48"
		ipv6MaskSize = 64

		networkConfigName = "test-network-config"
		vlan              = uint16(1001)
		v4NetMask         = 24
		v4Route1Dst       = "10.10.100.0/24"
		v4Route1Gw        = "10.10.100.254"
		v4Route2Dst       = "10.10.200.0/24"
		v6NetMask         = 96
		v6Route1Dst       = "fd00:200:1::/96"
		v6Route1Gw        = "fd00:200:1::1"
		v6Route2Dst       = "fd00:200:2::/96"
	)

	rawParam, err := json.Marshal(map[string]string{"networkConfig": networkConfigName})
	assert.NoError(t, err)

	claims := []*resourceapi.ResourceClaim{
		{
			ObjectMeta: metav1.ObjectMeta{
				Name:      claimName,
				Namespace: claimNamespace,
				UID:       claimUID,
			},
			Status: v1.ResourceClaimStatus{
				Allocation: &v1.AllocationResult{
					Devices: v1.DeviceAllocationResult{
						Config: []v1.DeviceAllocationConfiguration{
							{
								Source:   v1.AllocationConfigSourceClaim,
								Requests: []string{request},
								DeviceConfiguration: v1.DeviceConfiguration{
									Opaque: &v1.OpaqueDeviceConfiguration{
										Driver: driverName,
										Parameters: runtime.RawExtension{
											Raw: rawParam,
										},
									},
								},
							},
						},
						Results: []v1.DeviceRequestAllocationResult{
							{
								Device:  device,
								Driver:  driverName,
								Pool:    devicePool,
								Request: request,
							},
						},
					},
				},
				ReservedFor: []v1.ResourceClaimConsumerReference{
					{
						Resource: claimConsumerResource,
						Name:     ClaimConsumerName,
						UID:      ClaimConsumerUID,
					},
				},
			},
		},
	}

	resourceIPPool := v2alpha1.CiliumResourceIPPool{
		ObjectMeta: metav1.ObjectMeta{
			Name: ipPoolName,
		},
		Spec: v2alpha1.ResourceIPPoolSpec{
			IPv4: &v2alpha1.IPv4PoolSpec{
				CIDRs: []v2alpha1.PoolCIDR{
					v2alpha1.PoolCIDR(ipv4CIDR),
				},
				MaskSize: uint8(ipv4MaskSize),
			},
			IPv6: &v2alpha1.IPv6PoolSpec{
				CIDRs: []v2alpha1.PoolCIDR{
					v2alpha1.PoolCIDR(ipv6CIDR),
				},
				MaskSize: uint8(ipv6MaskSize),
			},
		},
	}

	resourceNetCfg := v2alpha1.CiliumResourceNetworkConfig{
		ObjectMeta: metav1.ObjectMeta{
			Name: networkConfigName,
		},
		Spec: []v2alpha1.CiliumResourceNetworkConfigSpec{
			{
				NodeSelector: &slimv1.LabelSelector{
					MatchLabels: map[string]slimv1.MatchLabelsValue{
						"kubernetes.io/hostname": localNodeName,
					},
				},
				IPPool: ipPoolName,
				VLAN:   vlan,
				IPv4: &v2alpha1.IPv4NetworkConfigSpec{
					NetMask: uint8(v4NetMask),
					StaticRoutes: []v2alpha1.IPv4StaticRouteSpec{
						{
							Destination: v4Route1Dst,
							Gateway:     v4Route1Gw,
						},
						{
							Destination: v4Route2Dst,
						},
					},
				},
				IPv6: &v2alpha1.IPv6NetworkConfigSpec{
					NetMask: uint8(v6NetMask),
					StaticRoutes: []v2alpha1.IPv6StaticRouteSpec{
						{
							Destination: v6Route1Dst,
							Gateway:     v6Route1Gw,
						},
						{
							Destination: v6Route2Dst,
						},
					},
				},
			},
		},
	}

	var (
		mgr             *ipam.MultiPoolManager
		cs              *k8sClient.FakeClientset
		pods            resource.Resource[*corev1.Pod]
		db              *statedb.DB
		resourceNetCfgs statedb.Table[resourceNetworkConfig]
	)

	hive := hive.New(
		k8sClient.FakeClientCell(),
		k8s.ResourcesCell,
		cell.Provide(
			podResource,
			func() *option.DaemonConfig {
				return daemonCfg
			},
			func() promise.Promise[synced.CRDSync] {
				r, p := promise.New[synced.CRDSync]()
				r.Resolve(synced.CRDSync{})
				return p
			},
			newResourceNetworkConfigTableAndReflector,
		),
		operatoripam.Cell,
		resourceIPAM,

		cell.Invoke(func(c *k8sClient.FakeClientset) {
			for i := range len(claims) {
				current, err := c.KubernetesFakeClientset.ResourceV1().ResourceClaims(claims[i].Namespace).Create(t.Context(), claims[i], metav1.CreateOptions{})
				claims[i].SetResourceVersion(current.ResourceVersion)
				assert.NoError(t, err)
			}

			_, err := c.CiliumFakeClientset.CiliumV2alpha1().CiliumResourceIPPools().Create(t.Context(), &resourceIPPool, metav1.CreateOptions{})
			assert.NoError(t, err)

			_, err = c.CiliumFakeClientset.CiliumV2alpha1().CiliumResourceNetworkConfigs().Create(t.Context(), &resourceNetCfg, metav1.CreateOptions{})
			assert.NoError(t, err)

			nodetypes.SetName(localNodeName)
			localNode := v2.CiliumNode{
				ObjectMeta: metav1.ObjectMeta{
					Name: localNodeName,
					Labels: map[string]string{
						"kubernetes.io/hostname": "test-local-node",
					},
				},
			}
			_, err = c.CiliumFakeClientset.CiliumV2().CiliumNodes().Create(t.Context(), &localNode, metav1.CreateOptions{})
			assert.NoError(t, err)
		}),
		cell.Invoke(func(
			m *ipam.MultiPoolManager,
			c *k8sClient.FakeClientset,
			p resource.Resource[*corev1.Pod],
			d *statedb.DB,
			netCfgs statedb.Table[resourceNetworkConfig],
		) {
			mgr = m
			cs = c
			pods = p
			db = d
			resourceNetCfgs = netCfgs
		}),
	)

	tlog := hivetest.Logger(t)
	assert.NoError(t, hive.Start(tlog, t.Context()))

	// wait for the reflector to propagate CiliumResourceNetworkConfig upsert into stateDB
	var found bool
	for !found {
		_, _, watch, found := resourceNetCfgs.GetWatch(db.ReadTxn(), ResourceNetworkConfigByName(networkConfigName))
		if found {
			break
		}
		<-watch
	}

	driver := &Driver{
		logger:     tlog,
		kubeClient: cs,
		pods:       pods,
		config: &v2alpha1.CiliumNetworkDriverNodeConfigSpec{
			DriverName: driverName,
		},
		devices: map[types.DeviceManagerType][]types.Device{
			types.DeviceManagerTypeDummy: {
				&dummy.DummyDevice{
					Name: device,
				},
			},
		},
		allocations:            make(map[kubetypes.UID]map[kubetypes.UID][]allocation),
		multiPoolMgr:           mgr,
		ipv4Enabled:            daemonCfg.IPv4Enabled(),
		ipv6Enabled:            daemonCfg.IPv6Enabled(),
		db:                     db,
		resourceNetworkConfigs: resourceNetCfgs,
		localNodeStore: node.NewTestLocalNodeStore(node.LocalNode{
			Node: nodetypes.Node{
				Name: localNodeName,
				Labels: map[string]string{
					"kubernetes.io/hostname": "test-local-node",
				},
			},
		}),
	}

	if driver.ipv4Enabled {
		driver.multiPoolMgr.RestoreFinished(ipam.IPv4)
	}
	if driver.ipv6Enabled {
		driver.multiPoolMgr.RestoreFinished(ipam.IPv6)
	}

	results, err := driver.PrepareResourceClaims(t.Context(), claims)
	assert.NoError(t, err)
	assert.Contains(t, results, claimUID)
	assert.NoError(t, results[claimUID].Err)

	claim, err := cs.Clientset.ResourceV1().ResourceClaims(claimNamespace).Get(t.Context(), claimName, metav1.GetOptions{})
	assert.NoError(t, err)

	assert.Len(t, claim.Status.Devices, 1)
	assert.Equal(t, driverName, claim.Status.Devices[0].Driver)
	assert.Equal(t, devicePool, claim.Status.Devices[0].Pool)
	assert.Equal(t, device, claim.Status.Devices[0].Device)
	assert.Len(t, claim.Status.Devices[0].Conditions, 1)
	assert.Equal(t, "Ready", claim.Status.Devices[0].Conditions[0].Type)
	assert.Equal(t, metav1.ConditionTrue, claim.Status.Devices[0].Conditions[0].Status)

	var curLocalNode *v2.CiliumNode
	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		var err error
		curLocalNode, err = cs.CiliumFakeClientset.CiliumV2().CiliumNodes().Get(t.Context(), localNodeName, metav1.GetOptions{})
		assert.NoError(c, err)
		assert.Equal(c, []ipamtypes.IPAMPoolRequest{
			{
				Pool: ipPoolName,
				Needed: ipamtypes.IPAMPoolDemand{
					IPv4Addrs: 1,
					IPv6Addrs: 1,
				},
			},
		}, curLocalNode.Spec.IPAM.ResourcePools.Requested)
		assert.Len(c, curLocalNode.Spec.IPAM.ResourcePools.Allocated, 1)
	}, 10*time.Second, 100*time.Millisecond)
	assert.NotNil(t, curLocalNode)
	assert.Len(t, curLocalNode.Spec.IPAM.ResourcePools.Allocated, 1)
	assert.Equal(t, ipPoolName, curLocalNode.Spec.IPAM.ResourcePools.Allocated[0].Pool)

	v4PoolCIDR, v6PoolCIDR := netip.MustParsePrefix(ipv4CIDR), netip.MustParsePrefix(ipv6CIDR)

	var v4NodeCIDR, v6NodeCIDR netip.Prefix
	nodeCIDRs := curLocalNode.Spec.IPAM.ResourcePools.Allocated[0].CIDRs
	for _, cidr := range nodeCIDRs {
		if cidr.Addr().Is6() {
			v6NodeCIDR = cidr.Prefix
		} else {
			v4NodeCIDR = cidr.Prefix
		}
	}

	// allocated IP addresses must be contained in both the pool CIDR and the
	// sub-CIDR assigned to the node.
	var alloc allocation
	assert.NoError(t, json.Unmarshal(claim.Status.Devices[0].Data.Raw, &alloc))
	assert.Equal(t, ipPoolName, alloc.Config.IPPool)
	assert.Equal(t, vlan, alloc.Config.Vlan)

	assert.Equal(t, v4NetMask, alloc.Config.IPv4Addr.Bits())
	assert.True(t, v4PoolCIDR.Contains(alloc.Config.IPv4Addr.Masked().Addr()))
	assert.True(t, v4NodeCIDR.Contains(alloc.Config.IPv4Addr.Masked().Addr()))

	assert.Equal(t, v6NetMask, alloc.Config.IPv6Addr.Bits())
	assert.True(t, v6PoolCIDR.Contains(alloc.Config.IPv6Addr.Masked().Addr()))
	assert.True(t, v6NodeCIDR.Contains(alloc.Config.IPv6Addr.Masked().Addr()))

	assert.ElementsMatch(t,
		[]types.Route{
			{Destination: netip.MustParsePrefix(v4Route1Dst), Gateway: netip.MustParseAddr(v4Route1Gw)},
			{Destination: netip.MustParsePrefix(v4Route2Dst)},
			{Destination: netip.MustParsePrefix(v6Route1Dst), Gateway: netip.MustParseAddr(v6Route1Gw)},
			{Destination: netip.MustParsePrefix(v6Route2Dst)},
		},
		alloc.Config.Routes,
	)

	assert.Equal(t, device, claim.Status.Devices[0].NetworkData.InterfaceName)
	addrs := []string{alloc.Config.IPv4Addr.String(), alloc.Config.IPv6Addr.String()}
	assert.ElementsMatch(t, addrs, claim.Status.Devices[0].NetworkData.IPs)

	claimsToRelease := []kubeletplugin.NamespacedObject{
		{
			NamespacedName: kubetypes.NamespacedName{
				Namespace: claimNamespace,
				Name:      claimName,
			},
			UID: claimUID,
		},
	}

	releaseResults, err := driver.UnprepareResourceClaims(t.Context(), claimsToRelease)
	assert.NoError(t, err)
	assert.Contains(t, releaseResults, claimUID)
	assert.NoError(t, releaseResults[claimUID])

	// CIDR assigned to node must be returned to the operator
	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		localNode, err := cs.CiliumFakeClientset.CiliumV2().CiliumNodes().Get(t.Context(), localNodeName, metav1.GetOptions{})
		assert.NoError(c, err)
		assert.Empty(c, localNode.Spec.IPAM.ResourcePools.Requested)
		assert.Empty(c, localNode.Spec.IPAM.ResourcePools.Allocated)
	}, 10*time.Second, 100*time.Millisecond)

	assert.NoError(t, hive.Stop(tlog, t.Context()))
}

// TestSerializeDeserializeDevice round-trips a DummyDevice through
// serializeDevice / deserializeDevice and verifies the fields survive.
func TestSerializeDeserializeDevice(t *testing.T) {
	dev := &dummy.DummyDevice{Name: "eth0", HWAddr: "aa:bb:cc:dd:ee:ff", MTU: 1500}
	cfg := types.DeviceConfig{IPPool: "pool-a"}
	a := allocation{Device: dev, Config: cfg, Manager: types.DeviceManagerTypeDummy}

	raw, err := serializeDevice(a)
	require.NoError(t, err)

	mgr, devRaw, gotCfg, err := deserializeDevice(raw)
	require.NoError(t, err)
	require.Equal(t, types.DeviceManagerTypeDummy, mgr)
	require.Equal(t, cfg.IPPool, gotCfg.IPPool)
	require.NotEmpty(t, devRaw)
}

func TestDeviceClaimConfigs(t *testing.T) {
	driver := &Driver{
		logger:      hivetest.Logger(t),
		allocations: make(map[kubetypes.UID]map[kubetypes.UID][]allocation),
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

func TestPrepareResourceClaimPlainDevice(t *testing.T) {
	var pods resource.Resource[*corev1.Pod]
	var cs *k8sClient.FakeClientset

	h := hive.New(
		k8sClient.FakeClientCell(),
		k8s.ResourcesCell,
		cell.Provide(
			podResource,
			func() *option.DaemonConfig {
				return &option.DaemonConfig{
					EnableCiliumNetworkDriver: true,
					EnableIPv4:                true,
					EnableIPv6:                true,
				}
			},
		),
		cell.Invoke(func(c *k8sClient.FakeClientset, p resource.Resource[*corev1.Pod]) {
			cs = c
			pods = p
		}),
	)

	tlog := hivetest.Logger(t)
	assert.NoError(t, h.Start(tlog, t.Context()))
	t.Cleanup(func() { h.Stop(tlog, context.Background()) })

	require.NotNil(t, pods, "pod resource must be wired by hive")

	driver := &Driver{
		logger:     hivetest.Logger(t),
		kubeClient: cs,
		pods:       pods,
		config: &v2alpha1.CiliumNetworkDriverNodeConfigSpec{
			DriverName: "testdriver",
		},
		devices: map[types.DeviceManagerType][]types.Device{
			types.DeviceManagerTypeDummy: {&trackedDevice{name: "mydevice"}},
		},
		allocations: make(map[kubetypes.UID]map[kubetypes.UID][]allocation),
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
				Devices: v1.DeviceAllocationResult{
					Results: []v1.DeviceRequestAllocationResult{
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
}

// TestPrepareResourceClaim_AlreadyAllocated verifies that a second prepare
// for the same pod UID is rejected with errAllocationAlreadyExistsForPod.
func TestPrepareResourceClaim_AlreadyAllocated(t *testing.T) {
	podUID := kubetypes.UID("existing-pod-uid")
	driver := &Driver{
		logger: hivetest.Logger(t),
		allocations: map[kubetypes.UID]map[kubetypes.UID][]allocation{
			podUID: {},
		},
	}
	claim := &resourceapi.ResourceClaim{
		Status: resourceapi.ResourceClaimStatus{
			ReservedFor: []resourceapi.ResourceClaimConsumerReference{
				{Resource: "pods", UID: podUID},
			},
			Allocation: &resourceapi.AllocationResult{},
		},
	}
	res := driver.prepareResourceClaim(t.Context(), claim)
	require.Error(t, res.Err)
	require.ErrorIs(t, res.Err, errAllocationAlreadyExistsForPod)
}

// TestAddressesForClaim_NilPod verifies that a nil pod returns nil without error.
func TestAddressesForClaim_NilPod(t *testing.T) {
	addrs, err := addressesForClaim(nil, "my-claim")
	require.NoError(t, err)
	require.Nil(t, addrs)
}

func TestAnnotationAddresses(t *testing.T) {
	t.Run("no annotation", func(t *testing.T) {
		pod := &corev1.Pod{}
		addrs, err := addressesForClaim(pod, "my-claim")
		require.NoError(t, err)
		require.Nil(t, addrs)
	})

	t.Run("invalid json", func(t *testing.T) {
		pod := &corev1.Pod{}
		pod.Annotations = map[string]string{
			annotation.NetworkDriverStaticAddresses: "not-json",
		}
		_, err := addressesForClaim(pod, "my-claim")
		require.Error(t, err)
	})
}

func TestApplyAddressToConfig(t *testing.T) {
	driver := &Driver{logger: hivetest.Logger(t)}

	t.Run("empty address", func(t *testing.T) {
		claim := &resourceapi.ResourceClaim{ObjectMeta: metav1.ObjectMeta{Name: "test"}}
		devicesCfg := map[string]types.DeviceConfig{"req": {}}
		err := driver.applyAddressToConfig(claim, "req", netip.Prefix{}, devicesCfg)
		require.NoError(t, err, "zero prefix should be skipped without error")
	})

	t.Run("request not found", func(t *testing.T) {
		claim := &resourceapi.ResourceClaim{ObjectMeta: metav1.ObjectMeta{Name: "test"}}
		err := driver.applyAddressToConfig(claim, "missing-req", netip.MustParsePrefix("10.0.0.1/32"), map[string]types.DeviceConfig{})
		require.Error(t, err)
	})
}

func TestNetConfigForDeviceVLANPrecedence(t *testing.T) {
	db := statedb.New()
	resourceNetCfgs, err := NewResourceNetworkConfigTable(db)
	assert.NoError(t, err)

	const networkConfigName = "test-network-config"
	const networkConfigVLAN = uint16(1001)
	const deviceConfigVLAN = uint16(1002)

	wtxn := db.WriteTxn(resourceNetCfgs)
	_, _, err = resourceNetCfgs.Insert(wtxn, resourceNetworkConfig{
		Name: networkConfigName,
		Specs: []spec{
			{
				NodeSelector: labels.Everything(),
				Vlan:         networkConfigVLAN,
			},
		},
		UpdatedAt: time.Now(),
	})
	assert.NoError(t, err)
	wtxn.Commit()

	driver := &Driver{
		db:                     db,
		resourceNetworkConfigs: resourceNetCfgs,
		localNodeStore: node.NewTestLocalNodeStore(node.LocalNode{
			Node: nodetypes.Node{},
		}),
	}

	tests := []struct {
		name string
		cfg  types.DeviceConfig
		want uint16
	}{
		{
			name: "network config vlan is used when device config vlan is unset",
			cfg: types.DeviceConfig{
				NetworkConfig: networkConfigName,
			},
			want: networkConfigVLAN,
		},
		{
			name: "device config vlan takes precedence when set",
			cfg: types.DeviceConfig{
				NetworkConfig: networkConfigName,
				Vlan:          deviceConfigVLAN,
			},
			want: deviceConfigVLAN,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			devCfg, err := driver.netConfigForDevice(t.Context(), "test-device", tt.cfg)
			assert.NoError(t, err)
			assert.Equal(t, tt.want, devCfg.vlan)
		})
	}
}
