// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package networkdriver

import (
	"context"
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

	"github.com/cilium/cilium/daemon/k8s"
	"github.com/cilium/cilium/pkg/annotation"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client/testutils"
	"github.com/cilium/cilium/pkg/k8s/resource"
	"github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/labels"
	"github.com/cilium/cilium/pkg/networkdriver/dummy"
	"github.com/cilium/cilium/pkg/networkdriver/types"
	"github.com/cilium/cilium/pkg/node"
	nodetypes "github.com/cilium/cilium/pkg/node/types"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/time"
)

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

// TestPrepareResourceClaim_AlreadyAllocatedSameClaim verifies that a second
// prepare for the exact same (pod, claim) pair is idempotent: when the claim
// has no devices to set up (empty Results), the call succeeds without error.
func TestPrepareResourceClaim_AlreadyAllocatedSameClaim(t *testing.T) {
	tlog := hivetest.Logger(t)
	cs, _ := k8sClient.NewFakeClientset(tlog)

	podUID := kubetypes.UID("existing-pod-uid")
	claimUID := kubetypes.UID("existing-claim-uid")

	driver := buildPrepDriver(t, cs)
	driver.allocations = map[kubetypes.UID]map[kubetypes.UID][]allocation{
		podUID: {claimUID: {}},
	}

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
