// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package networkdriver

// Tests for prepareResourceClaim covering:
//
//   - driver.allocations is written only after UpdateStatus
//     succeeds; if UpdateStatus fails the map stays empty.
//     this avoids keeping a local map entry that does not have a
//     persistent reference in kubernetes
//
//   - when any step inside the device loop fails, rollback
//     calls Device.Free() and releaseAddrs() for every previously set-up device.
//     this avoids leftover state that can end up untracked
//
// Tests build a *Driver directly (no hive) using a fake Kubernetes client and
// instrumented device stubs so they run without a real cluster or kernel
// privileges.

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	resourceapi "k8s.io/api/resource/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	kubetypes "k8s.io/apimachinery/pkg/types"
	"k8s.io/dynamic-resource-allocation/kubeletplugin"

	"github.com/cilium/cilium/pkg/annotation"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client/testutils"
	"github.com/cilium/cilium/pkg/k8s/resource"
	"github.com/cilium/cilium/pkg/networkdriver/types"
)

// ---------------------------------------------------------------------------
// Instrumented device stub
// ---------------------------------------------------------------------------

// trackedDevice is a minimal types.Device implementation that records calls
// to Setup and Free and can be configured to return errors on either.
type trackedDevice struct {
	name       string
	setupErr   error
	freeErr    error
	setupCalls atomic.Int32
	freeCalls  atomic.Int32
	setupCfgs  []types.DeviceConfig
}

func (d *trackedDevice) IfName() string       { return d.name }
func (d *trackedDevice) KernelIfName() string { return d.name }

func (d *trackedDevice) GetAttrs() map[resourceapi.QualifiedName]resourceapi.DeviceAttribute {
	return nil
}

func (d *trackedDevice) Setup(cfg types.DeviceConfig) error {
	d.setupCalls.Add(1)
	d.setupCfgs = append(d.setupCfgs, cfg)
	return d.setupErr
}

func (d *trackedDevice) Free(_ types.DeviceConfig) error {
	d.freeCalls.Add(1)
	return d.freeErr
}

func (d *trackedDevice) Match(_ v2alpha1.CiliumNetworkDriverDeviceFilter) bool { return true }

func (d *trackedDevice) MarshalBinary() ([]byte, error) {
	return json.Marshal(map[string]string{"name": d.name})
}

func (d *trackedDevice) UnmarshalBinary(data []byte) error {
	m := map[string]string{}
	if err := json.Unmarshal(data, &m); err != nil {
		return err
	}
	d.name = m["name"]
	return nil
}

// ---------------------------------------------------------------------------
// Constants shared by all tests
// ---------------------------------------------------------------------------

const (
	prepTestDriverName = "test.cilium.k8s.io"
	prepTestPool       = "test-pool"
	prepTestRequest    = "req-0"
	prepTestClaimNS    = "default"
	prepTestClaimName  = "test-claim"
	prepTestClaimUID   = kubetypes.UID("aaaaaaaa-0000-0000-0000-000000000001")
	prepTestPodName    = "test-pod"
	prepTestPodUID     = kubetypes.UID("bbbbbbbb-0000-0000-0000-000000000002")
	prepTestDev0       = "dev-0"
	prepTestDev1       = "dev-1"
)

// ---------------------------------------------------------------------------
// Fixture builders
// ---------------------------------------------------------------------------

// buildPrepClaim returns a ResourceClaim whose Results request the given
// device names. Static IPv4/IPv6 addresses are embedded in the opaque config
// so no IPAM pool manager is needed.
func buildPrepClaim(devices ...string) *resourceapi.ResourceClaim {
	rawParam, _ := json.Marshal(map[string]string{
		"ipv4Addr": "10.1.0.1/32",
		"ipv6Addr": "fd00::1/128",
	})

	results := make([]resourceapi.DeviceRequestAllocationResult, 0, len(devices))
	for _, d := range devices {
		results = append(results, resourceapi.DeviceRequestAllocationResult{
			Device:  d,
			Driver:  prepTestDriverName,
			Pool:    prepTestPool,
			Request: prepTestRequest,
		})
	}

	return &resourceapi.ResourceClaim{
		ObjectMeta: metav1.ObjectMeta{
			Name:            prepTestClaimName,
			Namespace:       prepTestClaimNS,
			UID:             prepTestClaimUID,
			ResourceVersion: "1",
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
					Results: results,
				},
			},
			ReservedFor: []resourceapi.ResourceClaimConsumerReference{
				{Resource: "pods", Name: prepTestPodName, UID: prepTestPodUID},
			},
		},
	}
}

// buildGeneratedPrepClaim returns a ResourceClaim like buildPrepClaim does,
// but generates the claim name using the pod, the claim name and a random suffix,
// to mimic a ResourceClaim generated from a ResourceClaimTemplate.
// This is needed to test the logic that looks up the original claim name in the annotation when the claim is generated.
func buildGeneratedPrepClaim(devices ...string) *resourceapi.ResourceClaim {
	claim := buildPrepClaim(devices...)
	claim.Name = strings.Join([]string{prepTestPodName, prepTestClaimName, "4qttt"}, "-")
	claim.Annotations = map[string]string{
		"resource.kubernetes.io/pod-claim-name": prepTestClaimName,
	}
	return claim
}

// buildPrepDriver builds a *Driver with a fake kube client and the given
// devices pre-populated in driver.devices. No IPAM pool manager is wired
// because all test claims use static IP addresses (releaseAddrs is a no-op
// when IPPool == "").
func buildPrepDriver(t *testing.T, cs *k8sClient.FakeClientset, devs ...*trackedDevice) *Driver {
	t.Helper()

	deviceList := make([]types.Device, 0, len(devs))
	for _, d := range devs {
		deviceList = append(deviceList, d)
	}

	// hive is used to provide the pods resource only
	var pods resource.Resource[*corev1.Pod]
	hive := hive.New(
		k8sClient.FakeClientCell(),
		cell.Provide(
			podResource,
		),
		cell.Invoke(func(p resource.Resource[*corev1.Pod]) {
			pods = p
		}),
	)
	tlog := hivetest.Logger(t)
	assert.NoError(t, hive.Start(tlog, t.Context()))
	t.Cleanup(func() { hive.Stop(tlog, context.Background()) })

	return &Driver{
		logger:     hivetest.Logger(t),
		kubeClient: cs,
		pods:       pods,
		config: &v2alpha1.CiliumNetworkDriverNodeConfigSpec{
			DriverName: prepTestDriverName,
		},
		devices: map[types.DeviceManagerType][]types.Device{
			types.DeviceManagerTypeDummy: deviceList,
		},
		allocations: make(map[kubetypes.UID]map[kubetypes.UID][]allocation),
		// ipv4Enabled/ipv6Enabled left false so releaseAddrs is always a no-op.
	}
}

// createPrepClaim pre-creates the claim in the fake API server and updates
// the ResourceVersion on the local object so subsequent UpdateStatus works.
func createPrepClaim(t *testing.T, cs *k8sClient.FakeClientset, claim *resourceapi.ResourceClaim) {
	t.Helper()
	updated, err := cs.KubernetesFakeClientset.ResourceV1().
		ResourceClaims(claim.Namespace).Create(context.Background(), claim, metav1.CreateOptions{})
	require.NoError(t, err)
	claim.ResourceVersion = updated.ResourceVersion
}

func createPod(t *testing.T, cs *k8sClient.FakeClientset, annotations map[string]string) {
	t.Helper()
	_, err := cs.KubernetesFakeClientset.CoreV1().
		Pods(prepTestClaimNS).Create(context.Background(), &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:        "test-pod",
			Namespace:   prepTestClaimNS,
			UID:         prepTestPodUID,
			Annotations: annotations,
		},
	}, metav1.CreateOptions{})
	require.NoError(t, err)
}

// namedObject is a small helper to build a kubeletplugin.NamespacedObject.
func namedObject(ns, name string, uid kubetypes.UID) kubeletplugin.NamespacedObject {
	return kubeletplugin.NamespacedObject{
		NamespacedName: kubetypes.NamespacedName{Namespace: ns, Name: name},
		UID:            uid,
	}
}

// ---------------------------------------------------------------------------
// Tests — happy path
// ---------------------------------------------------------------------------

// TestPrepare_Success verifies the happy path: device is set up, Kubernetes
// status is updated, and the allocation is committed to memory.
func TestPrepare_Success(t *testing.T) {
	tlog := hivetest.Logger(t)
	cs, _ := k8sClient.NewFakeClientset(tlog)
	dev := &trackedDevice{name: prepTestDev0}
	claim := buildPrepClaim(prepTestDev0)
	createPrepClaim(t, cs, claim)

	driver := buildPrepDriver(t, cs, dev)
	result := driver.prepareResourceClaim(t.Context(), claim)
	require.NoError(t, result.Err)

	assert.EqualValues(t, 1, dev.setupCalls.Load(), "Setup must be called once")
	assert.EqualValues(t, 0, dev.freeCalls.Load(), "Free must not be called on success")

	require.Contains(t, driver.allocations, prepTestPodUID)
	require.Contains(t, driver.allocations[prepTestPodUID], prepTestClaimUID)
	assert.Len(t, driver.allocations[prepTestPodUID][prepTestClaimUID], 1)

	updated, err := cs.KubernetesFakeClientset.ResourceV1().
		ResourceClaims(prepTestClaimNS).Get(t.Context(), prepTestClaimName, metav1.GetOptions{})
	require.NoError(t, err)
	assert.Len(t, updated.Status.Devices, 1)
	assert.Equal(t, prepTestDev0, updated.Status.Devices[0].Device)
}

// TestPrepare_TwoDevices_BothSucceed verifies that two devices in one claim
// both get set up and both appear in the allocation map.
func TestPrepare_TwoDevices_BothSucceed(t *testing.T) {
	tlog := hivetest.Logger(t)
	cs, _ := k8sClient.NewFakeClientset(tlog)

	dev0 := &trackedDevice{name: prepTestDev0}
	dev1 := &trackedDevice{name: prepTestDev1}

	claim := buildPrepClaim(prepTestDev0, prepTestDev1)
	createPrepClaim(t, cs, claim)

	driver := buildPrepDriver(t, cs, dev0, dev1)
	result := driver.prepareResourceClaim(t.Context(), claim)
	require.NoError(t, result.Err)

	assert.EqualValues(t, 1, dev0.setupCalls.Load())
	assert.EqualValues(t, 1, dev1.setupCalls.Load())
	assert.EqualValues(t, 0, dev0.freeCalls.Load())
	assert.EqualValues(t, 0, dev1.freeCalls.Load())

	require.Contains(t, driver.allocations, prepTestPodUID)
	assert.Len(t, driver.allocations[prepTestPodUID][prepTestClaimUID], 2)

	updated, err := cs.KubernetesFakeClientset.ResourceV1().
		ResourceClaims(prepTestClaimNS).Get(t.Context(), prepTestClaimName, metav1.GetOptions{})
	require.NoError(t, err)
	assert.Len(t, updated.Status.Devices, 2)
}

func TestPrepare_PodStaticIPsAnnotation(t *testing.T) {
	testCases := []struct {
		name        string
		annotation  map[string]types.StaticAddrsMap
		ipv4Enabled bool
		ipv6Enabled bool
		expectedIPs []string
	}{
		{
			name: "IPv4 and IPv6 on dual stack",
			annotation: map[string]types.StaticAddrsMap{
				prepTestClaimName: {
					prepTestRequest: {
						IPv4: netip.MustParsePrefix("10.44.0.9/24"),
						IPv6: netip.MustParsePrefix("fdaa::1/128"),
					},
				},
			},
			ipv4Enabled: true,
			ipv6Enabled: true,
			expectedIPs: []string{"10.44.0.9/24", "fdaa::1/128"}, // IPs from annotation must be used instead of defaults in claim config
		},
		{
			name: "IPv4 and IPv6 on v4 single stack",
			annotation: map[string]types.StaticAddrsMap{
				prepTestClaimName: {
					prepTestRequest: {
						IPv4: netip.MustParsePrefix("10.44.0.9/24"),
						IPv6: netip.MustParsePrefix("fdaa::1/128"),
					},
				},
			},
			ipv4Enabled: true,
			ipv6Enabled: false,
			expectedIPs: []string{"10.44.0.9/24"}, // IPv4 from annotation must be used instead of defaults in claim config
		},
		{
			name: "IPv4 and IPv6 on v6 single stack",
			annotation: map[string]types.StaticAddrsMap{
				prepTestClaimName: {
					prepTestRequest: {
						IPv4: netip.MustParsePrefix("10.44.0.9/24"),
						IPv6: netip.MustParsePrefix("fdaa::1/128"),
					},
				},
			},
			ipv4Enabled: false,
			ipv6Enabled: true,
			expectedIPs: []string{"fdaa::1/128"}, // IPv6 from annotation must be used instead of defaults in claim config
		},
		{
			name: "IPv4 only on dual stack",
			annotation: map[string]types.StaticAddrsMap{
				prepTestClaimName: {
					prepTestRequest: {
						IPv4: netip.MustParsePrefix("10.44.0.9/24"),
					},
				},
			},
			ipv4Enabled: true,
			ipv6Enabled: true,
			expectedIPs: []string{"10.44.0.9/24", "fd00::1/128"}, // IPv4 from annotation, IPv6 from claim config (annotation must not override missing IP family)
		},
		{
			name: "IPv6 only on dual stack",
			annotation: map[string]types.StaticAddrsMap{
				prepTestClaimName: {
					prepTestRequest: {
						IPv6: netip.MustParsePrefix("fdaa::1/128"),
					},
				},
			},
			ipv4Enabled: true,
			ipv6Enabled: true,
			expectedIPs: []string{"10.1.0.1/32", "fdaa::1/128"}, // IPv4 from claim config (annotation must not override missing IP family), IPv6 from annotation
		},
	}

	claimCases := []struct {
		name          string
		generateClaim func(devices ...string) *resourceapi.ResourceClaim
	}{
		{
			name:          "From ResourceClaim",
			generateClaim: buildPrepClaim,
		},
		{
			name:          "From ResourceClaimTemplate",
			generateClaim: buildGeneratedPrepClaim,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			for _, cc := range claimCases {
				t.Run(cc.name, func(t *testing.T) {
					tlog := hivetest.Logger(t)
					cs, _ := k8sClient.NewFakeClientset(tlog)

					dev := &trackedDevice{name: prepTestDev0}
					claim := cc.generateClaim(prepTestDev0)
					createPrepClaim(t, cs, claim)

					staticIPs, err := json.Marshal(tc.annotation)
					require.NoError(t, err)

					createPod(t, cs, map[string]string{
						annotation.NetworkDriverStaticAddresses: string(staticIPs),
					})

					driver := buildPrepDriver(t, cs, dev)
					driver.ipv4Enabled = tc.ipv4Enabled
					driver.ipv6Enabled = tc.ipv6Enabled

					result := driver.prepareResourceClaim(t.Context(), claim)
					require.NoError(t, result.Err)

					require.Len(t, dev.setupCfgs, 1)
					var addrs []string
					if dev.setupCfgs[0].IPv4Addr.IsValid() {
						addrs = append(addrs, dev.setupCfgs[0].IPv4Addr.String())
					}
					if dev.setupCfgs[0].IPv6Addr.IsValid() {
						addrs = append(addrs, dev.setupCfgs[0].IPv6Addr.String())
					}
					require.ElementsMatch(t, tc.expectedIPs, addrs)

					updated, err := cs.KubernetesFakeClientset.ResourceV1().
						ResourceClaims(prepTestClaimNS).Get(t.Context(), claim.Name, metav1.GetOptions{})
					require.NoError(t, err)
					require.Len(t, updated.Status.Devices, 1)
					require.ElementsMatch(t, tc.expectedIPs, updated.Status.Devices[0].NetworkData.IPs)
				})
			}
		})
	}
}

func TestPrepare_PodStaticIPsAnnotation_Errors(t *testing.T) {
	claimCases := []struct {
		name          string
		generateClaim func(devices ...string) *resourceapi.ResourceClaim
	}{
		{
			name:          "From ResourceClaim",
			generateClaim: buildPrepClaim,
		},
		{
			name:          "From ResourceClaimTemplate",
			generateClaim: buildGeneratedPrepClaim,
		},
	}

	for _, cc := range claimCases {
		t.Run(cc.name, func(t *testing.T) {
			tlog := hivetest.Logger(t)
			cs, _ := k8sClient.NewFakeClientset(tlog)

			dev := &trackedDevice{name: prepTestDev0}
			claim := buildPrepClaim(prepTestDev0)
			createPrepClaim(t, cs, claim)

			staticIPs, err := json.Marshal(map[string]types.StaticAddrsMap{
				prepTestClaimName: {
					"other-request": {IPv4: netip.MustParsePrefix("10.44.0.9/24")},
				},
			})
			require.NoError(t, err)

			createPod(t, cs, map[string]string{
				annotation.NetworkDriverStaticAddresses: string(staticIPs),
			})

			driver := buildPrepDriver(t, cs, dev)

			result := driver.prepareResourceClaim(t.Context(), claim)
			require.Error(t, result.Err) // request name in annotation doesn't match any request in claim config → error expected
		})
	}
}

// TestPrepare_UpdateStatusFails_MapEmpty verifies that
// when UpdateStatus returns an error the allocations map must stay empty.
func TestPrepare_UpdateStatusFails_MapEmpty(t *testing.T) {
	tlog := hivetest.Logger(t)
	cs, _ := k8sClient.NewFakeClientset(tlog)
	dev := &trackedDevice{name: prepTestDev0}

	// Claim is NOT created in the API server → UpdateStatus will fail with
	// "not found".
	claim := buildPrepClaim(prepTestDev0)

	driver := buildPrepDriver(t, cs, dev)
	result := driver.prepareResourceClaim(t.Context(), claim)
	require.Error(t, result.Err, "UpdateStatus should fail because claim was not pre-created")

	// no partial entry must be left in the map.
	assert.Empty(t, driver.allocations,
		"allocations map must be empty when UpdateStatus fails")
}

// TestPrepare_UpdateStatusFails_RollbackCalled verifies that roll back
// is also triggered by an UpdateStatus failure: Setup was called, so Free
// must be called to roll back the device.
func TestPrepare_UpdateStatusFails_RollbackCalled(t *testing.T) {
	tlog := hivetest.Logger(t)
	cs, _ := k8sClient.NewFakeClientset(tlog)
	dev := &trackedDevice{name: prepTestDev0}

	// Claim not in API → UpdateStatus fails.
	claim := buildPrepClaim(prepTestDev0)

	driver := buildPrepDriver(t, cs, dev)
	result := driver.prepareResourceClaim(t.Context(), claim)
	require.Error(t, result.Err)

	assert.EqualValues(t, 1, dev.setupCalls.Load(), "Setup should have been attempted")
	assert.EqualValues(t, 1, dev.freeCalls.Load(),
		"Free must be called to roll back when UpdateStatus fails")
}

// TestPrepare_UpdateStatusFails_TwoDevices_BothRolledBack verifies that
// the logic works correctly when two devices were set up before
// UpdateStatus fails.
func TestPrepare_UpdateStatusFails_TwoDevices_BothRolledBack(t *testing.T) {
	tlog := hivetest.Logger(t)
	cs, _ := k8sClient.NewFakeClientset(tlog)

	dev0 := &trackedDevice{name: prepTestDev0}
	dev1 := &trackedDevice{name: prepTestDev1}

	// Claim not in API → UpdateStatus fails after both devices are set up.
	claim := buildPrepClaim(prepTestDev0, prepTestDev1)

	driver := buildPrepDriver(t, cs, dev0, dev1)
	result := driver.prepareResourceClaim(t.Context(), claim)
	require.Error(t, result.Err)

	assert.EqualValues(t, 1, dev0.setupCalls.Load())
	assert.EqualValues(t, 1, dev1.setupCalls.Load())
	assert.EqualValues(t, 1, dev0.freeCalls.Load(), "dev0 must be rolled back")
	assert.EqualValues(t, 1, dev1.freeCalls.Load(), "dev1 must be rolled back")
	assert.Empty(t, driver.allocations)
}

// TestPrepare_SecondSetupFails_FirstRolledBack verifies that
// when the second device's Setup fails, the first (already set up) device
// must be freed.
func TestPrepare_SecondSetupFails_FirstRolledBack(t *testing.T) {
	tlog := hivetest.Logger(t)
	cs, _ := k8sClient.NewFakeClientset(tlog)

	dev0 := &trackedDevice{name: prepTestDev0}
	dev1 := &trackedDevice{name: prepTestDev1, setupErr: errors.New("setup exploded")}

	claim := buildPrepClaim(prepTestDev0, prepTestDev1)
	createPrepClaim(t, cs, claim)

	driver := buildPrepDriver(t, cs, dev0, dev1)
	result := driver.prepareResourceClaim(t.Context(), claim)
	require.Error(t, result.Err)
	assert.Contains(t, result.Err.Error(), "setup exploded")

	// dev0 succeeded → must be freed by rollback.
	assert.EqualValues(t, 1, dev0.setupCalls.Load())
	assert.EqualValues(t, 1, dev0.freeCalls.Load(),
		"dev0 must be freed after dev1 Setup fails")

	// dev1 failed → Setup returned error, so Free must NOT be called for it.
	assert.EqualValues(t, 1, dev1.setupCalls.Load())
	assert.EqualValues(t, 0, dev1.freeCalls.Load(),
		"dev1 Free must not be called because its Setup failed")

	assert.Empty(t, driver.allocations)
}

// TestPrepare_DeviceNotFound_PreviousRolledBack verifies that
// when a requested device is not found in driver.devices, all previously
// set-up devices must be freed.
func TestPrepare_DeviceNotFound_PreviousRolledBack(t *testing.T) {
	tlog := hivetest.Logger(t)
	cs, _ := k8sClient.NewFakeClientset(tlog)

	dev0 := &trackedDevice{name: prepTestDev0}
	// prepTestDev1 is referenced in the claim but NOT registered in the driver.

	claim := buildPrepClaim(prepTestDev0, prepTestDev1)
	createPrepClaim(t, cs, claim)

	driver := buildPrepDriver(t, cs, dev0) // only dev0 registered
	result := driver.prepareResourceClaim(t.Context(), claim)
	require.Error(t, result.Err)
	assert.ErrorIs(t, result.Err, errDeviceNotFound)

	// dev0 was set up before the not-found error → must be freed.
	assert.EqualValues(t, 1, dev0.setupCalls.Load())
	assert.EqualValues(t, 1, dev0.freeCalls.Load(),
		"dev0 must be freed when a later device is not found")

	assert.Empty(t, driver.allocations)
}

// TestPrepare_FirstSetupFails_NoRollbackNeeded verifies that when the very
// first device's Setup fails, rollback doesn't panic and no Free is called
// (nothing was successfully set up).
func TestPrepare_FirstSetupFails_NoRollbackNeeded(t *testing.T) {
	tlog := hivetest.Logger(t)
	cs, _ := k8sClient.NewFakeClientset(tlog)

	dev0 := &trackedDevice{name: prepTestDev0, setupErr: errors.New("first device broken")}

	claim := buildPrepClaim(prepTestDev0)
	createPrepClaim(t, cs, claim)

	driver := buildPrepDriver(t, cs, dev0)
	result := driver.prepareResourceClaim(t.Context(), claim)
	require.Error(t, result.Err)

	assert.EqualValues(t, 1, dev0.setupCalls.Load())
	assert.EqualValues(t, 0, dev0.freeCalls.Load(),
		"Free must not be called for the device whose own Setup failed")
	assert.Empty(t, driver.allocations)
}

// TestPrepare_RollbackFreeError_OriginalErrReturned verifies that a Free
// error during rollback does not shadow the original error that triggered it.
func TestPrepare_RollbackFreeError_OriginalErrReturned(t *testing.T) {
	tlog := hivetest.Logger(t)
	cs, _ := k8sClient.NewFakeClientset(tlog)

	setupKaboom := errors.New("setup kaboom")
	dev0 := &trackedDevice{name: prepTestDev0, freeErr: errors.New("free also failed")}
	dev1 := &trackedDevice{name: prepTestDev1, setupErr: setupKaboom}

	claim := buildPrepClaim(prepTestDev0, prepTestDev1)
	createPrepClaim(t, cs, claim)

	driver := buildPrepDriver(t, cs, dev0, dev1)
	result := driver.prepareResourceClaim(t.Context(), claim)
	require.Error(t, result.Err)

	// The original setup error is what the caller must see.
	assert.Contains(t, result.Err.Error(), "setup kaboom",
		"original error must propagate even when Free also fails")

	// Free was still attempted on dev0 despite returning an error itself.
	assert.EqualValues(t, 1, dev0.freeCalls.Load(),
		"Free must be attempted even when it will fail")

	assert.Empty(t, driver.allocations)
}

// ---------------------------------------------------------------------------
// Tests — early rejection paths
// ---------------------------------------------------------------------------

// TestPrepare_DuplicateClaimUID_Idempotent verifies that a second
// PrepareResourceClaims call for the same (pod, claim) pair succeeds without
// calling Setup again — all steps are already done.
func TestPrepare_DuplicateClaimUID_Idempotent(t *testing.T) {
	tlog := hivetest.Logger(t)
	cs, _ := k8sClient.NewFakeClientset(tlog)
	dev := &trackedDevice{name: prepTestDev0}
	claim := buildPrepClaim(prepTestDev0)
	createPrepClaim(t, cs, claim)

	driver := buildPrepDriver(t, cs, dev)

	// First call succeeds and sets up the device.
	result := driver.prepareResourceClaim(t.Context(), claim)
	require.NoError(t, result.Err)
	assert.EqualValues(t, 1, dev.setupCalls.Load(), "Setup must be called once on first prepare")

	// Update the ResourceVersion so that the second UpdateStatus (if any) works.
	updated, err := cs.KubernetesFakeClientset.ResourceV1().ResourceClaims(prepTestClaimNS).Get(t.Context(), prepTestClaimName, metav1.GetOptions{})
	require.NoError(t, err)
	claim.ResourceVersion = updated.ResourceVersion

	// Second call with the same claim must be idempotent: no error, no re-setup.
	result2 := driver.prepareResourceClaim(t.Context(), claim)
	require.NoError(t, result2.Err)
	assert.EqualValues(t, 1, dev.setupCalls.Load(), "Setup must NOT be called again on idempotent retry")
	assert.EqualValues(t, 0, dev.freeCalls.Load(), "Free must not be called")
}

const (
	prepTestClaimUID2  = kubetypes.UID("cccccccc-0000-0000-0000-000000000003")
	prepTestClaimName2 = "test-claim-2"
)

// buildPrepClaim2 builds a second distinct claim (different UID and name) for
// the same pod as buildPrepClaim, requesting the given devices.
func buildPrepClaim2(devices ...string) *resourceapi.ResourceClaim {
	c := buildPrepClaim(devices...)
	c.Name = prepTestClaimName2
	c.UID = prepTestClaimUID2
	return c
}

// TestPrepare_MultipleClaims_SamePod_Succeeds verifies that two distinct
// ResourceClaims for the same pod can both be prepared successfully, and that
// driver.allocations ends up with two entries under the pod's UID.
func TestPrepare_MultipleClaims_SamePod_Succeeds(t *testing.T) {
	tlog := hivetest.Logger(t)
	cs, _ := k8sClient.NewFakeClientset(tlog)

	dev0 := &trackedDevice{name: prepTestDev0}
	dev1 := &trackedDevice{name: prepTestDev1}

	claim1 := buildPrepClaim(prepTestDev0)
	claim2 := buildPrepClaim2(prepTestDev1)
	createPrepClaim(t, cs, claim1)
	createPrepClaim(t, cs, claim2)

	driver := buildPrepDriver(t, cs, dev0, dev1)

	result1 := driver.prepareResourceClaim(t.Context(), claim1)
	require.NoError(t, result1.Err, "first claim must succeed")

	result2 := driver.prepareResourceClaim(t.Context(), claim2)
	require.NoError(t, result2.Err, "second claim for the same pod must also succeed")

	assert.EqualValues(t, 1, dev0.setupCalls.Load(), "dev0 Setup must be called once")
	assert.EqualValues(t, 1, dev1.setupCalls.Load(), "dev1 Setup must be called once")

	require.Contains(t, driver.allocations, prepTestPodUID)
	assert.Len(t, driver.allocations[prepTestPodUID], 2, "allocations map must have 2 claim entries")
	assert.Contains(t, driver.allocations[prepTestPodUID], prepTestClaimUID)
	assert.Contains(t, driver.allocations[prepTestPodUID], prepTestClaimUID2)
}

// TestPrepare_CrossClaimDeviceConflict_Rejected verifies that a second claim
// for the same pod is rejected when it requests a device that is already
// allocated by a previously prepared claim for that pod.
func TestPrepare_CrossClaimDeviceConflict_Rejected(t *testing.T) {
	tlog := hivetest.Logger(t)
	cs, _ := k8sClient.NewFakeClientset(tlog)

	dev := &trackedDevice{name: prepTestDev0}

	// Both claims request the same device.
	claim1 := buildPrepClaim(prepTestDev0)
	claim2 := buildPrepClaim2(prepTestDev0)
	createPrepClaim(t, cs, claim1)
	createPrepClaim(t, cs, claim2)

	driver := buildPrepDriver(t, cs, dev)

	result1 := driver.prepareResourceClaim(t.Context(), claim1)
	require.NoError(t, result1.Err, "first claim must succeed")

	result2 := driver.prepareResourceClaim(t.Context(), claim2)
	require.Error(t, result2.Err, "second claim requesting the same device must be rejected")
	assert.Contains(t, result2.Err.Error(), prepTestDev0)

	// Setup must have been called only once (by the first claim).
	assert.EqualValues(t, 1, dev.setupCalls.Load(), "Setup must not be called for the conflicting claim")

	// The pod entry must only contain the first claim.
	require.Contains(t, driver.allocations, prepTestPodUID)
	assert.Len(t, driver.allocations[prepTestPodUID], 1)
	assert.Contains(t, driver.allocations[prepTestPodUID], prepTestClaimUID)
}

// TestPrepare_InvalidPodIfName_NoSetup verifies that podIfName validation
// happens before any Setup call.
func TestPrepare_InvalidPodIfName_NoSetup(t *testing.T) {
	tlog := hivetest.Logger(t)
	cs, _ := k8sClient.NewFakeClientset(tlog)
	dev := &trackedDevice{name: prepTestDev0}

	rawParam, _ := json.Marshal(map[string]string{
		"ipv4Addr":  "10.1.0.1/32",
		"ipv6Addr":  "fd00::1/128",
		"podIfName": "this-name-is-way-too-long-for-linux",
	})
	claim := buildPrepClaim(prepTestDev0)
	claim.Status.Allocation.Devices.Config[0].Opaque.Parameters = runtime.RawExtension{Raw: rawParam}
	createPrepClaim(t, cs, claim)

	driver := buildPrepDriver(t, cs, dev)
	result := driver.prepareResourceClaim(t.Context(), claim)
	require.Error(t, result.Err)

	assert.EqualValues(t, 0, dev.setupCalls.Load(),
		"Setup must not be called when podIfName validation fails")
	assert.Empty(t, driver.allocations)
}

// TestPrepare_WrongReservedForLength_Rejected verifies early rejection when
// ReservedFor has more than one entry.
func TestPrepare_WrongReservedForLength_Rejected(t *testing.T) {
	tlog := hivetest.Logger(t)
	cs, _ := k8sClient.NewFakeClientset(tlog)
	dev := &trackedDevice{name: prepTestDev0}

	claim := buildPrepClaim(prepTestDev0)
	claim.Status.ReservedFor = append(claim.Status.ReservedFor,
		resourceapi.ResourceClaimConsumerReference{Resource: "pods", Name: "other", UID: "cccc"})
	createPrepClaim(t, cs, claim)

	driver := buildPrepDriver(t, cs, dev)
	result := driver.prepareResourceClaim(t.Context(), claim)
	require.Error(t, result.Err)
	assert.ErrorIs(t, result.Err, errUnexpectedInput)
	assert.EqualValues(t, 0, dev.setupCalls.Load())
	assert.Empty(t, driver.allocations)
}

// ---------------------------------------------------------------------------
// Tests — UnprepareResourceClaims
// ---------------------------------------------------------------------------

// TestUnprepare_RemovesAllocationAndCallsFree verifies that
// UnprepareResourceClaims removes the pod entry from the allocations map and
// calls Free on the device.
func TestUnprepare_RemovesAllocationAndCallsFree(t *testing.T) {
	tlog := hivetest.Logger(t)
	cs, _ := k8sClient.NewFakeClientset(tlog)
	dev := &trackedDevice{name: prepTestDev0}
	claim := buildPrepClaim(prepTestDev0)
	createPrepClaim(t, cs, claim)

	driver := buildPrepDriver(t, cs, dev)

	result := driver.prepareResourceClaim(t.Context(), claim)
	require.NoError(t, result.Err)
	require.Contains(t, driver.allocations, prepTestPodUID)

	releaseResults, err := driver.UnprepareResourceClaims(t.Context(),
		[]kubeletplugin.NamespacedObject{namedObject(prepTestClaimNS, prepTestClaimName, prepTestClaimUID)})
	require.NoError(t, err)
	require.Contains(t, releaseResults, prepTestClaimUID)
	assert.NoError(t, releaseResults[prepTestClaimUID])

	assert.Empty(t, driver.allocations,
		"allocations map must be empty after unprepare")
	assert.EqualValues(t, 1, dev.freeCalls.Load(), "Free must be called once on unprepare")
}

// TestUnprepare_MultipleDevices_AllFreed verifies that every device in a
// multi-device claim is freed on unprepare.
func TestUnprepare_MultipleDevices_AllFreed(t *testing.T) {
	tlog := hivetest.Logger(t)
	cs, _ := k8sClient.NewFakeClientset(tlog)
	dev0 := &trackedDevice{name: prepTestDev0}
	dev1 := &trackedDevice{name: prepTestDev1}

	claim := buildPrepClaim(prepTestDev0, prepTestDev1)
	createPrepClaim(t, cs, claim)

	driver := buildPrepDriver(t, cs, dev0, dev1)

	result := driver.prepareResourceClaim(t.Context(), claim)
	require.NoError(t, result.Err)

	_, err := driver.UnprepareResourceClaims(t.Context(),
		[]kubeletplugin.NamespacedObject{namedObject(prepTestClaimNS, prepTestClaimName, prepTestClaimUID)})
	require.NoError(t, err)

	assert.EqualValues(t, 1, dev0.freeCalls.Load(), "dev0 must be freed")
	assert.EqualValues(t, 1, dev1.freeCalls.Load(), "dev1 must be freed")
	assert.Empty(t, driver.allocations)
}

// TestUnprepare_UnknownClaim_NoError verifies that unpreparing an unknown
// claim returns no error (it may simply not belong to this driver instance).
func TestUnprepare_UnknownClaim_NoError(t *testing.T) {
	tlog := hivetest.Logger(t)
	cs, _ := k8sClient.NewFakeClientset(tlog)

	driver := buildPrepDriver(t, cs)

	releaseResults, err := driver.UnprepareResourceClaims(t.Context(),
		[]kubeletplugin.NamespacedObject{namedObject(prepTestClaimNS, "nonexistent", "zzzz")})
	require.NoError(t, err)
	assert.NoError(t, releaseResults["zzzz"])
}

// TestUnprepare_PrepareRollbackThenPrepareAgain verifies that
// after a failed prepare (UpdateStatus error), a second prepare
// attempt for the same pod can succeed once the claim exists in the API.
func TestUnprepare_PrepareRollbackThenPrepareAgain(t *testing.T) {
	tlog := hivetest.Logger(t)
	cs, _ := k8sClient.NewFakeClientset(tlog)
	dev := &trackedDevice{name: prepTestDev0}
	claim := buildPrepClaim(prepTestDev0)

	driver := buildPrepDriver(t, cs, dev)

	// First attempt: claim not in API → UpdateStatus fails → rollback.
	result := driver.prepareResourceClaim(t.Context(), claim)
	require.Error(t, result.Err)
	assert.Empty(t, driver.allocations, "map must be clean after failed prepare")

	// Now create the claim in the API.
	createPrepClaim(t, cs, claim)

	// Second attempt: should succeed because the map is clean
	// (no "allocation already exists" guard fires).
	result2 := driver.prepareResourceClaim(t.Context(), claim)
	require.NoError(t, result2.Err, "second prepare must succeed after rollback cleaned up")

	require.Contains(t, driver.allocations, prepTestPodUID)
	assert.Len(t, driver.allocations[prepTestPodUID][prepTestClaimUID], 1)

	// Setup called twice (once per attempt), Free called once (rollback of first attempt).
	assert.EqualValues(t, 2, dev.setupCalls.Load())
	assert.EqualValues(t, 1, dev.freeCalls.Load())
}
