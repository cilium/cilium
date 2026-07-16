// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package networkdriver

import (
	"context"
	"testing"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	resourceapi "k8s.io/api/resource/v1"
	v1 "k8s.io/api/resource/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	kubetypes "k8s.io/apimachinery/pkg/types"

	"github.com/cilium/cilium/daemon/k8s"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client/testutils"
	"github.com/cilium/cilium/pkg/k8s/resource"
	"github.com/cilium/cilium/pkg/networkdriver/types"
	"github.com/cilium/cilium/pkg/option"
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
}

func TestDeviceClaimConfigs(t *testing.T) {
	tlog := hivetest.Logger(t)
	driver := &Driver{
		logger:      tlog,
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
			func(cfg *NetworkDriverConfig) {
				cfg.Enabled = true
			})

		require.NoError(t, h.Start(tlog, t.Context()))
		t.Cleanup(func() { h.Stop(tlog, context.Background()) })

		require.NotNil(t, pods, "pod resource must be wired by hive")

		driver := &Driver{
			logger:     tlog,
			kubeClient: cs,
			pods:       pods,
			config: &v2alpha1.CiliumNetworkDriverNodeConfigSpec{
				DriverName: "testdriver",
			},
			devices: map[types.DeviceManagerType][]types.Device{
				types.DeviceManagerTypeMock: {&trackedDevice{name: "mydevice"}},
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
	})

	t.Run("already allocated same claim is idempotent", func(t *testing.T) {
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
	})
}
