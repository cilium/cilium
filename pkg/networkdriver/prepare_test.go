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
	"sync/atomic"
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	resourceapi "k8s.io/api/resource/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	kubetypes "k8s.io/apimachinery/pkg/types"
	"k8s.io/dynamic-resource-allocation/kubeletplugin"

	"github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client/testutils"
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
}

func (d *trackedDevice) IfName() string       { return d.name }
func (d *trackedDevice) KernelIfName() string { return d.name }

func (d *trackedDevice) GetAttrs() map[resourceapi.QualifiedName]resourceapi.DeviceAttribute {
	return nil
}

func (d *trackedDevice) Setup(_ types.DeviceConfig) error {
	d.setupCalls.Add(1)
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

// trackedDeviceManager is a minimal types.DeviceManager that can restore
// trackedDevice instances from their serialized form.
type trackedDeviceManager struct{}

func (m *trackedDeviceManager) Type() types.DeviceManagerType {
	return types.DeviceManagerTypeDummy
}

func (m *trackedDeviceManager) ListDevices() ([]types.Device, error) { return nil, nil }

func (m *trackedDeviceManager) RestoreDevice(data []byte) (types.Device, error) {
	d := &trackedDevice{}
	if err := d.UnmarshalBinary(data); err != nil {
		return nil, err
	}
	return d, nil
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
				{Resource: "pods", Name: "test-pod", UID: prepTestPodUID},
			},
		},
	}
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

	return &Driver{
		logger:     hivetest.Logger(t),
		kubeClient: cs,
		config: &v2alpha1.CiliumNetworkDriverNodeConfigSpec{
			DriverName: prepTestDriverName,
		},
		devices: map[types.DeviceManagerType][]types.Device{
			types.DeviceManagerTypeDummy: deviceList,
		},
		deviceManagers: map[types.DeviceManagerType]types.DeviceManager{
			types.DeviceManagerTypeDummy: &trackedDeviceManager{},
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

// namedObject is a small helper to build a kubeletplugin.NamespacedObject.
func namedObject(ns, name string, uid kubetypes.UID) kubeletplugin.NamespacedObject {
	return kubeletplugin.NamespacedObject{
		NamespacedName: kubetypes.NamespacedName{Namespace: ns, Name: name},
		UID:            uid,
	}
}

// prepOne is a test-only helper that runs PrepareResourceClaims for a single
// claim and returns its result, mirroring the old prepareResourceClaim API.
func prepOne(t *testing.T, driver *Driver, claim *resourceapi.ResourceClaim) kubeletplugin.PrepareResult {
	t.Helper()
	results, err := driver.PrepareResourceClaims(t.Context(), []*resourceapi.ResourceClaim{claim})
	require.NoError(t, err)
	return results[claim.UID]
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
	result := prepOne(t, driver, claim)
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
	result := prepOne(t, driver, claim)
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
	result := prepOne(t, driver, claim)
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
	result := prepOne(t, driver, claim)
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
	result := prepOne(t, driver, claim)
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
	result := prepOne(t, driver, claim)
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
	result := prepOne(t, driver, claim)
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
	result := prepOne(t, driver, claim)
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
	result := prepOne(t, driver, claim)
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

// TestPrepare_DuplicateClaim_Idempotent verifies that preparing the same claim
// twice is a no-op: the second call succeeds without calling Setup again.
func TestPrepare_DuplicateClaim_Idempotent(t *testing.T) {
	tlog := hivetest.Logger(t)
	cs, _ := k8sClient.NewFakeClientset(tlog)
	dev := &trackedDevice{name: prepTestDev0}
	claim := buildPrepClaim(prepTestDev0)
	createPrepClaim(t, cs, claim)

	driver := buildPrepDriver(t, cs, dev)

	result := prepOne(t, driver, claim)
	require.NoError(t, result.Err)

	// Second call with the same claim must succeed and be a no-op.
	result2 := prepOne(t, driver, claim)
	require.NoError(t, result2.Err)

	// Setup must only have been called once.
	assert.EqualValues(t, 1, dev.setupCalls.Load())
	assert.Len(t, driver.allocations[prepTestPodUID][prepTestClaimUID], 1)
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
	result := prepOne(t, driver, claim)
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
	result := prepOne(t, driver, claim)
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

	result := prepOne(t, driver, claim)
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

	result := prepOne(t, driver, claim)
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
	result := prepOne(t, driver, claim)
	require.Error(t, result.Err)
	assert.Empty(t, driver.allocations, "map must be clean after failed prepare")

	// Now create the claim in the API.
	createPrepClaim(t, cs, claim)

	// Second attempt: should succeed because the map is clean
	// (no "allocation already exists" guard fires).
	result2 := prepOne(t, driver, claim)
	require.NoError(t, result2.Err, "second prepare must succeed after rollback cleaned up")

	require.Contains(t, driver.allocations, prepTestPodUID)
	assert.Len(t, driver.allocations[prepTestPodUID][prepTestClaimUID], 1)

	// Setup called twice (once per attempt), Free called once (rollback of first attempt).
	assert.EqualValues(t, 2, dev.setupCalls.Load())
	assert.EqualValues(t, 1, dev.freeCalls.Load())
}

// ---------------------------------------------------------------------------
// Tests — multiple claims per pod
// ---------------------------------------------------------------------------

const (
	prepTestClaimName2 = "test-claim-2"
	prepTestClaimUID2  = kubetypes.UID("aaaaaaaa-0000-0000-0000-000000000002")
)

// buildPrepClaimWithUID returns a claim with a custom name and UID so multiple
// distinct claims can be prepared for the same pod in one test.
func buildPrepClaimWithUID(name string, uid kubetypes.UID, devices ...string) *resourceapi.ResourceClaim {
	claim := buildPrepClaim(devices...)
	claim.Name = name
	claim.UID = uid
	return claim
}

// TestPrepare_TwoClaimsSamePod_BothSucceed verifies that a pod can prepare two
// distinct claims and both end up committed to the allocations map.
func TestPrepare_TwoClaimsSamePod_BothSucceed(t *testing.T) {
	tlog := hivetest.Logger(t)
	cs, _ := k8sClient.NewFakeClientset(tlog)

	dev0 := &trackedDevice{name: prepTestDev0}
	dev1 := &trackedDevice{name: prepTestDev1}

	claim1 := buildPrepClaimWithUID(prepTestClaimName, prepTestClaimUID, prepTestDev0)
	claim2 := buildPrepClaimWithUID(prepTestClaimName2, prepTestClaimUID2, prepTestDev1)

	createPrepClaim(t, cs, claim1)
	createPrepClaim(t, cs, claim2)

	driver := buildPrepDriver(t, cs, dev0, dev1)

	result1 := prepOne(t, driver, claim1)
	require.NoError(t, result1.Err)

	result2 := prepOne(t, driver, claim2)
	require.NoError(t, result2.Err)

	assert.EqualValues(t, 1, dev0.setupCalls.Load())
	assert.EqualValues(t, 1, dev1.setupCalls.Load())

	require.Contains(t, driver.allocations, prepTestPodUID)
	assert.Len(t, driver.allocations[prepTestPodUID], 2,
		"both claims must be present under the pod UID")
	assert.Contains(t, driver.allocations[prepTestPodUID], prepTestClaimUID)
	assert.Contains(t, driver.allocations[prepTestPodUID], prepTestClaimUID2)
}

// TestPrepare_DuplicateClaimSamePod_Idempotent verifies that preparing the same
// claim twice for the same pod is a no-op, while other claims are allowed.
func TestPrepare_DuplicateClaimSamePod_Idempotent(t *testing.T) {
	tlog := hivetest.Logger(t)
	cs, _ := k8sClient.NewFakeClientset(tlog)

	dev0 := &trackedDevice{name: prepTestDev0}
	dev1 := &trackedDevice{name: prepTestDev1}

	claim1 := buildPrepClaimWithUID(prepTestClaimName, prepTestClaimUID, prepTestDev0)
	claim2 := buildPrepClaimWithUID(prepTestClaimName2, prepTestClaimUID2, prepTestDev1)

	createPrepClaim(t, cs, claim1)
	createPrepClaim(t, cs, claim2)

	driver := buildPrepDriver(t, cs, dev0, dev1)

	require.NoError(t, prepOne(t, driver, claim1).Err)
	require.NoError(t, prepOne(t, driver, claim2).Err)

	// Repeating claim1 must be a no-op.
	result3 := prepOne(t, driver, claim1)
	require.NoError(t, result3.Err)

	// Setup was called once per device, not twice for claim1.
	assert.EqualValues(t, 1, dev0.setupCalls.Load())
	assert.EqualValues(t, 1, dev1.setupCalls.Load())
}

// TestUnprepare_TwoClaimsSamePod_UnprepareOne verifies that unpreparing one
// claim for a pod leaves the other claim intact in the allocations map.
func TestUnprepare_TwoClaimsSamePod_UnprepareOne(t *testing.T) {
	tlog := hivetest.Logger(t)
	cs, _ := k8sClient.NewFakeClientset(tlog)

	dev0 := &trackedDevice{name: prepTestDev0}
	dev1 := &trackedDevice{name: prepTestDev1}

	claim1 := buildPrepClaimWithUID(prepTestClaimName, prepTestClaimUID, prepTestDev0)
	claim2 := buildPrepClaimWithUID(prepTestClaimName2, prepTestClaimUID2, prepTestDev1)

	createPrepClaim(t, cs, claim1)
	createPrepClaim(t, cs, claim2)

	driver := buildPrepDriver(t, cs, dev0, dev1)

	require.NoError(t, prepOne(t, driver, claim1).Err)
	require.NoError(t, prepOne(t, driver, claim2).Err)

	// Unprepare only claim1.
	_, err := driver.UnprepareResourceClaims(t.Context(),
		[]kubeletplugin.NamespacedObject{namedObject(prepTestClaimNS, prepTestClaimName, prepTestClaimUID)})
	require.NoError(t, err)

	assert.EqualValues(t, 1, dev0.freeCalls.Load(), "dev0 must be freed")
	assert.EqualValues(t, 0, dev1.freeCalls.Load(), "dev1 must not be freed")

	// Pod entry must still exist with claim2.
	require.Contains(t, driver.allocations, prepTestPodUID,
		"pod entry must remain after partial unprepare")
	assert.Contains(t, driver.allocations[prepTestPodUID], prepTestClaimUID2,
		"claim2 must still be allocated")
	assert.NotContains(t, driver.allocations[prepTestPodUID], prepTestClaimUID,
		"claim1 must be removed")
}

// TestPrepare_CrossClaimPodIfNameCollision_Rejected verifies that a claim
// whose podIfName collides with one already allocated to the same pod from a
// previous claim is rejected before any Setup call.
func TestPrepare_CrossClaimPodIfNameCollision_Rejected(t *testing.T) {
	tlog := hivetest.Logger(t)
	cs, _ := k8sClient.NewFakeClientset(tlog)

	dev0 := &trackedDevice{name: prepTestDev0}
	dev1 := &trackedDevice{name: prepTestDev1}

	sharedIfName := "eth0"

	rawParam, _ := json.Marshal(map[string]string{
		"ipv4Addr":  "10.1.0.1/32",
		"ipv6Addr":  "fd00::1/128",
		"podIfName": sharedIfName,
	})

	makeClaim := func(name string, uid kubetypes.UID, dev string) *resourceapi.ResourceClaim {
		c := buildPrepClaimWithUID(name, uid, dev)
		c.Status.Allocation.Devices.Config[0].Opaque.Parameters = runtime.RawExtension{Raw: rawParam}
		return c
	}

	claim1 := makeClaim(prepTestClaimName, prepTestClaimUID, prepTestDev0)
	claim2 := makeClaim(prepTestClaimName2, prepTestClaimUID2, prepTestDev1)

	createPrepClaim(t, cs, claim1)
	createPrepClaim(t, cs, claim2)

	driver := buildPrepDriver(t, cs, dev0, dev1)

	// First claim succeeds.
	require.NoError(t, prepOne(t, driver, claim1).Err)
	assert.EqualValues(t, 1, dev0.setupCalls.Load())

	// Second claim with the same podIfName must be rejected before Setup.
	result := prepOne(t, driver, claim2)
	require.Error(t, result.Err)
	assert.ErrorIs(t, result.Err, errUnexpectedInput)
	assert.Contains(t, result.Err.Error(), sharedIfName)

	assert.EqualValues(t, 0, dev1.setupCalls.Load(),
		"Setup must not be called when podIfName collides with existing allocation")
}

// TestPrepare_CrossClaimDeviceCollision_Rejected verifies that a claim
// requesting a device already allocated to the same pod (via another claim)
// is rejected before any Setup call.
func TestPrepare_CrossClaimDeviceCollision_Rejected(t *testing.T) {
	tlog := hivetest.Logger(t)
	cs, _ := k8sClient.NewFakeClientset(tlog)

	dev0 := &trackedDevice{name: prepTestDev0}

	// Both claims request the same device.
	claim1 := buildPrepClaimWithUID(prepTestClaimName, prepTestClaimUID, prepTestDev0)
	claim2 := buildPrepClaimWithUID(prepTestClaimName2, prepTestClaimUID2, prepTestDev0)

	createPrepClaim(t, cs, claim1)
	createPrepClaim(t, cs, claim2)

	driver := buildPrepDriver(t, cs, dev0)

	// First claim succeeds.
	require.NoError(t, prepOne(t, driver, claim1).Err)
	assert.EqualValues(t, 1, dev0.setupCalls.Load())

	// Second claim requesting the same device must be rejected.
	result := prepOne(t, driver, claim2)
	require.Error(t, result.Err)
	assert.ErrorIs(t, result.Err, errUnexpectedInput)
	assert.Contains(t, result.Err.Error(), prepTestDev0)

	// Setup must not have been called again.
	assert.EqualValues(t, 1, dev0.setupCalls.Load(),
		"Setup must not be called when device is already allocated to the pod")
}

// TestPrepare_NilOpaqueConfig_NoPanic verifies that a claim whose device
// config has a nil Opaque field does not panic and is handled gracefully.
func TestPrepare_NilOpaqueConfig_NoPanic(t *testing.T) {
	tlog := hivetest.Logger(t)
	cs, _ := k8sClient.NewFakeClientset(tlog)
	dev := &trackedDevice{name: prepTestDev0}

	claim := buildPrepClaim(prepTestDev0)
	// Wipe the Opaque field entirely.
	claim.Status.Allocation.Devices.Config[0].DeviceConfiguration.Opaque = nil
	createPrepClaim(t, cs, claim)

	driver := buildPrepDriver(t, cs, dev)

	// Must not panic; the result may be an error or success depending on
	// whether a nil-config device is valid — what matters is no panic.
	require.NotPanics(t, func() {
		_ = prepOne(t, driver, claim)
	})
}

// ---------------------------------------------------------------------------
// Tests — edge cases
// ---------------------------------------------------------------------------

// TestPrepare_NilAllocation_Rejected verifies that a claim with no Allocation
// is rejected before any Setup call.
func TestPrepare_NilAllocation_Rejected(t *testing.T) {
	tlog := hivetest.Logger(t)
	cs, _ := k8sClient.NewFakeClientset(tlog)
	dev := &trackedDevice{name: prepTestDev0}

	claim := buildPrepClaim(prepTestDev0)
	claim.Status.Allocation = nil

	driver := buildPrepDriver(t, cs, dev)
	result := prepOne(t, driver, claim)
	require.Error(t, result.Err)
	assert.ErrorIs(t, result.Err, errUnexpectedInput)
	assert.EqualValues(t, 0, dev.setupCalls.Load())
}

// TestPrepare_NonPodConsumer_Rejected verifies that a claim reserved for a
// non-pod resource (e.g. a Job) is rejected.
func TestPrepare_NonPodConsumer_Rejected(t *testing.T) {
	tlog := hivetest.Logger(t)
	cs, _ := k8sClient.NewFakeClientset(tlog)
	dev := &trackedDevice{name: prepTestDev0}

	claim := buildPrepClaim(prepTestDev0)
	claim.Status.ReservedFor[0].Resource = "jobs"

	driver := buildPrepDriver(t, cs, dev)
	result := prepOne(t, driver, claim)
	require.Error(t, result.Err)
	assert.ErrorIs(t, result.Err, errUnexpectedInput)
	assert.EqualValues(t, 0, dev.setupCalls.Load())
}

// TestPrepare_DuplicateDeviceInClaim_Rejected verifies that a claim listing
// the same device twice is rejected before any Setup call.
func TestPrepare_DuplicateDeviceInClaim_Rejected(t *testing.T) {
	tlog := hivetest.Logger(t)
	cs, _ := k8sClient.NewFakeClientset(tlog)
	dev := &trackedDevice{name: prepTestDev0}

	// Build a claim that lists the same device twice.
	claim := buildPrepClaim(prepTestDev0, prepTestDev0)
	createPrepClaim(t, cs, claim)

	driver := buildPrepDriver(t, cs, dev)
	result := prepOne(t, driver, claim)
	require.Error(t, result.Err)
	assert.ErrorIs(t, result.Err, errUnexpectedInput)
	assert.Contains(t, result.Err.Error(), prepTestDev0)
	assert.EqualValues(t, 0, dev.setupCalls.Load())
}

// TestPrepare_DuplicatePodIfNameWithinClaim_Rejected verifies that two devices
// in the same claim requesting the same podIfName are rejected before Setup.
func TestPrepare_DuplicatePodIfNameWithinClaim_Rejected(t *testing.T) {
	tlog := hivetest.Logger(t)
	cs, _ := k8sClient.NewFakeClientset(tlog)
	dev0 := &trackedDevice{name: prepTestDev0}
	dev1 := &trackedDevice{name: prepTestDev1}

	sharedIfName := "net0"
	rawParam, _ := json.Marshal(map[string]string{
		"ipv4Addr":  "10.1.0.1/32",
		"ipv6Addr":  "fd00::1/128",
		"podIfName": sharedIfName,
	})

	claim := buildPrepClaim(prepTestDev0, prepTestDev1)
	claim.Status.Allocation.Devices.Config[0].Opaque.Parameters = runtime.RawExtension{Raw: rawParam}
	createPrepClaim(t, cs, claim)

	driver := buildPrepDriver(t, cs, dev0, dev1)
	result := prepOne(t, driver, claim)
	require.Error(t, result.Err)
	assert.ErrorIs(t, result.Err, errUnexpectedInput)
	assert.Contains(t, result.Err.Error(), sharedIfName)
	assert.EqualValues(t, 0, dev0.setupCalls.Load())
	assert.EqualValues(t, 0, dev1.setupCalls.Load())
}

// TestPrepare_CrashBeforeMapWrite_RestoredFromStatus verifies that if
// UpdateStatus succeeded in a previous run but the driver crashed before
// writing to driver.allocations, a subsequent PrepareResourceClaims call
// restores the allocation from claim.Status.Devices without calling Setup again.
func TestPrepare_CrashBeforeMapWrite_RestoredFromStatus(t *testing.T) {
	tlog := hivetest.Logger(t)
	cs, _ := k8sClient.NewFakeClientset(tlog)
	dev := &trackedDevice{name: prepTestDev0}
	claim := buildPrepClaim(prepTestDev0)
	createPrepClaim(t, cs, claim)

	driver := buildPrepDriver(t, cs, dev)

	// Simulate a successful first prepare.
	result := prepOne(t, driver, claim)
	require.NoError(t, result.Err)
	assert.EqualValues(t, 1, dev.setupCalls.Load())

	// Simulate crash-before-map-write: clear the in-memory allocations but
	// leave Status.Devices intact in the API (as a real crash would).
	driver.allocations = make(map[kubetypes.UID]map[kubetypes.UID][]allocation)

	// Fetch the updated claim from the API (has Status.Devices populated).
	updatedClaim, err := cs.KubernetesFakeClientset.ResourceV1().
		ResourceClaims(prepTestClaimNS).Get(t.Context(), prepTestClaimName, metav1.GetOptions{})
	require.NoError(t, err)

	// Second prepare must restore from Status.Devices without calling Setup again.
	result2 := prepOne(t, driver, updatedClaim)
	require.NoError(t, result2.Err)

	assert.EqualValues(t, 1, dev.setupCalls.Load(),
		"Setup must not be called again when restoring from existing Status.Devices")

	require.Contains(t, driver.allocations, prepTestPodUID)
	assert.Len(t, driver.allocations[prepTestPodUID][prepTestClaimUID], 1)
}

// TestPrepareBatch_SecondClaimFails_FirstRolledBack verifies that when
// PrepareResourceClaims processes a batch and the second claim fails, the
// first (already prepared) claim is rolled back atomically.
func TestPrepareBatch_SecondClaimFails_FirstRolledBack(t *testing.T) {
	tlog := hivetest.Logger(t)
	cs, _ := k8sClient.NewFakeClientset(tlog)

	dev0 := &trackedDevice{name: prepTestDev0}
	dev1 := &trackedDevice{name: prepTestDev1}

	claim1 := buildPrepClaimWithUID(prepTestClaimName, prepTestClaimUID, prepTestDev0)
	// claim2 is NOT created in the API, so its UpdateStatus will fail.
	claim2 := buildPrepClaimWithUID(prepTestClaimName2, prepTestClaimUID2, prepTestDev1)

	createPrepClaim(t, cs, claim1)
	// claim2 intentionally not created.

	driver := buildPrepDriver(t, cs, dev0, dev1)

	results, err := driver.PrepareResourceClaims(t.Context(), []*resourceapi.ResourceClaim{claim1, claim2})
	require.NoError(t, err, "PrepareResourceClaims itself must not return an error")

	// claim1 should have succeeded initially then been rolled back.
	// claim2 failed.
	assert.Error(t, results[prepTestClaimUID2].Err, "claim2 must have failed")

	// After batch rollback, allocations map must be empty.
	assert.Empty(t, driver.allocations,
		"allocations must be empty after batch rollback when one claim fails")

	// dev0 was set up then freed (rolled back).
	assert.EqualValues(t, 1, dev0.setupCalls.Load(), "dev0 Setup must have been called")
	assert.EqualValues(t, 1, dev0.freeCalls.Load(), "dev0 must have been freed during batch rollback")
}
