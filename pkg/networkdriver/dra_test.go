// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package networkdriver

import (
	"encoding/json"
	"net/netip"
	"testing"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/assert"
	resourceapi "k8s.io/api/resource/v1"
	v1 "k8s.io/api/resource/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	kubetypes "k8s.io/apimachinery/pkg/types"
	"k8s.io/dynamic-resource-allocation/kubeletplugin"

	"github.com/cilium/cilium/daemon/k8s"
	operatoripam "github.com/cilium/cilium/operator/pkg/networkdriver/ipam"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/ipam"
	ipamtypes "github.com/cilium/cilium/pkg/ipam/types"
	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client/testutils"
	"github.com/cilium/cilium/pkg/networkdriver/dummy"
	"github.com/cilium/cilium/pkg/networkdriver/types"
	nodetypes "github.com/cilium/cilium/pkg/node/types"
	"github.com/cilium/cilium/pkg/option"
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
		mgr *ipam.MultiPoolManager
		cs  *k8sClient.FakeClientset
	)

	hive := hive.New(
		k8sClient.FakeClientCell(),
		k8s.LocalNodeCell,
		cell.Provide(func() *option.DaemonConfig {
			return daemonCfg
		}),
		resourceIPAM,

		cell.Invoke(func(c *k8sClient.FakeClientset) {
			for _, claim := range claims {
				_, err := c.KubernetesFakeClientset.ResourceV1().ResourceClaims(claim.Namespace).Create(t.Context(), claim, metav1.CreateOptions{})
				assert.NoError(t, err)
			}
		}),
		cell.Invoke(func(m *ipam.MultiPoolManager, c *k8sClient.FakeClientset) {
			mgr = m
			cs = c
		}),
	)

	tlog := hivetest.Logger(t)
	assert.NoError(t, hive.Start(tlog, t.Context()))

	driver := &Driver{
		logger:     tlog,
		kubeClient: cs,
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
	)

	rawParam, err := json.Marshal(map[string]string{"ip-pool": ipPoolName})
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

	var (
		mgr *ipam.MultiPoolManager
		cs  *k8sClient.FakeClientset
	)

	hive := hive.New(
		k8sClient.FakeClientCell(),
		k8s.ResourcesCell,
		cell.Provide(func() *option.DaemonConfig {
			return daemonCfg
		}),
		operatoripam.Cell,
		resourceIPAM,

		cell.Invoke(func(c *k8sClient.FakeClientset) {
			for _, claim := range claims {
				_, err := c.KubernetesFakeClientset.ResourceV1().ResourceClaims(claim.Namespace).Create(t.Context(), claim, metav1.CreateOptions{})
				assert.NoError(t, err)
			}

			_, err := c.CiliumFakeClientset.CiliumV2alpha1().CiliumResourceIPPools().Create(t.Context(), &resourceIPPool, metav1.CreateOptions{})
			assert.NoError(t, err)

			nodetypes.SetName(localNodeName)
			localNode := v2.CiliumNode{
				ObjectMeta: metav1.ObjectMeta{
					Name: localNodeName,
				},
			}
			_, err = c.CiliumFakeClientset.CiliumV2().CiliumNodes().Create(t.Context(), &localNode, metav1.CreateOptions{})
			assert.NoError(t, err)
		}),
		cell.Invoke(func(m *ipam.MultiPoolManager, c *k8sClient.FakeClientset) {
			mgr = m
			cs = c
		}),
	)

	tlog := hivetest.Logger(t)
	assert.NoError(t, hive.Start(tlog, t.Context()))

	driver := &Driver{
		logger:     tlog,
		kubeClient: cs,
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

	curLocalNode, err := cs.CiliumFakeClientset.CiliumV2().CiliumNodes().Get(t.Context(), localNodeName, metav1.GetOptions{})
	assert.NoError(t, err)

	assert.Equal(t, []ipamtypes.IPAMPoolRequest{
		{
			Pool: ipPoolName,
			Needed: ipamtypes.IPAMPoolDemand{
				IPv4Addrs: 1,
				IPv6Addrs: 1,
			},
		},
	}, curLocalNode.Spec.IPAM.ResourcePools.Requested)
	assert.Len(t, curLocalNode.Spec.IPAM.ResourcePools.Allocated, 1)
	assert.Equal(t, ipPoolName, curLocalNode.Spec.IPAM.ResourcePools.Allocated[0].Pool)

	v4PoolCIDR, v6PoolCIDR := netip.MustParsePrefix(ipv4CIDR), netip.MustParsePrefix(ipv6CIDR)

	var v4NodeCIDR, v6NodeCIDR netip.Prefix
	nodeCIDRs := curLocalNode.Spec.IPAM.ResourcePools.Allocated[0].CIDRs
	for _, cidr := range nodeCIDRs {
		prefix, err := cidr.ToPrefix()
		assert.NoError(t, err)
		if prefix.Addr().Is6() {
			v6NodeCIDR = *prefix
		} else {
			v4NodeCIDR = *prefix
		}
	}

	// allocated IP addresses must be contained in both the pool CIDR and the
	// sub-CIDR assigned to the node.
	var alloc allocation
	assert.NoError(t, json.Unmarshal(claim.Status.Devices[0].Data.Raw, &alloc))
	assert.Equal(t, ipPoolName, alloc.Config.IPPool)
	assert.Equal(t, 32, alloc.Config.IPv4Addr.Bits())
	assert.True(t, v4PoolCIDR.Contains(alloc.Config.IPv4Addr.Masked().Addr()))
	assert.True(t, v4NodeCIDR.Contains(alloc.Config.IPv4Addr.Masked().Addr()))
	assert.Equal(t, 128, alloc.Config.IPv6Addr.Bits())
	assert.True(t, v6PoolCIDR.Contains(alloc.Config.IPv6Addr.Masked().Addr()))
	assert.True(t, v6NodeCIDR.Contains(alloc.Config.IPv6Addr.Masked().Addr()))

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
