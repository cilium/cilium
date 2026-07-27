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
	"strings"
	"sync/atomic"
	"testing"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	resourceapi "k8s.io/api/resource/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	kubetypes "k8s.io/apimachinery/pkg/types"
	k8stesting "k8s.io/client-go/testing"
	"k8s.io/dynamic-resource-allocation/kubeletplugin"

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
	prepTestRequest    = "req-0"
	prepTestClaimNS    = "default"
	prepTestClaimName  = "test-claim"
	prepTestClaimUID   = kubetypes.UID("aaaaaaaa-0000-0000-0000-000000000001")
	prepTestPodName    = "test-pod"
	prepTestPodUID     = kubetypes.UID("bbbbbbbb-0000-0000-0000-000000000002")
	prepTestDev0       = "dev-0"
	prepTestDev1       = "dev-1"
	prepTestClaimUID2  = kubetypes.UID("cccccccc-0000-0000-0000-000000000003")
	prepTestClaimName2 = "test-claim-2"
	prepTestPool       = "testpool"
)

// ---------------------------------------------------------------------------
// Fixture builders
// ---------------------------------------------------------------------------

// buildPrepClaim returns a ResourceClaim whose Results request the given
// device names.
func buildPrepClaim(devices ...string) *resourceapi.ResourceClaim {
	rawParam, _ := json.Marshal(map[string]string{
		"podIfName": "mydevice",
	})

	results := make([]resourceapi.DeviceRequestAllocationResult, 0, len(devices))
	for _, d := range devices {
		results = append(results, resourceapi.DeviceRequestAllocationResult{
			Device:  d,
			Driver:  prepTestDriverName,
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

// buildPrepClaim2 builds a second distinct claim (different UID and name) for
// the same pod as buildPrepClaim, requesting the given devices.
func buildPrepClaim2(devices ...string) *resourceapi.ResourceClaim {
	c := buildPrepClaim(devices...)
	c.Name = prepTestClaimName2
	c.UID = prepTestClaimUID2
	return c
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
// devices pre-populated in driver.devices.
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
	require.NoError(t, hive.Start(tlog, t.Context()))
	t.Cleanup(func() { hive.Stop(tlog, context.Background()) })

	return &Driver{
		logger:     hivetest.Logger(t),
		kubeClient: cs,
		pods:       pods,
		config: &v2alpha1.CiliumNetworkDriverNodeConfigSpec{
			DriverName: prepTestDriverName,
		},
		devices: map[types.DeviceManagerType][]types.Device{
			types.DeviceManagerTypeMock: deviceList,
		},
		allocations: make(map[kubetypes.UID]map[kubetypes.UID][]allocation),
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

// prepOne calls PrepareResourceClaims for a single claim and returns the
// per-claim result. The caller must not expect a top-level error.
func prepOne(t *testing.T, driver *Driver, claim *resourceapi.ResourceClaim) kubeletplugin.PrepareResult {
	t.Helper()
	results, err := driver.PrepareResourceClaims(t.Context(), []*resourceapi.ResourceClaim{claim})
	require.NoError(t, err)
	return results[claim.UID]
}

// namedObject is a small helper to build a kubeletplugin.NamespacedObject.
func namedObject(ns, name string, uid kubetypes.UID) kubeletplugin.NamespacedObject {
	return kubeletplugin.NamespacedObject{
		NamespacedName: kubetypes.NamespacedName{Namespace: ns, Name: name},
		UID:            uid,
	}
}

func TestPrepare(t *testing.T) {
	tlog := hivetest.Logger(t)

	t.Run("test prepare one device one claim success", func(t *testing.T) {
		cs, _ := k8sClient.NewFakeClientset(tlog)
		dev := &trackedDevice{name: prepTestDev0}
		claim := buildPrepClaim(prepTestDev0)
		createPrepClaim(t, cs, claim)

		driver := buildPrepDriver(t, cs, dev)
		result := prepOne(t, driver, claim)
		require.NoError(t, result.Err)

		require.EqualValues(t, 1, dev.setupCalls.Load(), "Setup must be called once")
		require.EqualValues(t, 0, dev.freeCalls.Load(), "Free must not be called on success")

		require.Contains(t, driver.allocations, prepTestPodUID)
		require.Contains(t, driver.allocations[prepTestPodUID], prepTestClaimUID)
		require.Len(t, driver.allocations[prepTestPodUID][prepTestClaimUID], 1)

		updated, err := cs.KubernetesFakeClientset.ResourceV1().
			ResourceClaims(prepTestClaimNS).Get(t.Context(), prepTestClaimName, metav1.GetOptions{})
		require.NoError(t, err)
		require.Len(t, updated.Status.Devices, 1)
		require.Equal(t, prepTestDev0, updated.Status.Devices[0].Device)
	})

	t.Run("test prepare two devices one claim success", func(t *testing.T) {
		cs, _ := k8sClient.NewFakeClientset(tlog)
		dev0 := &trackedDevice{name: prepTestDev0}
		dev1 := &trackedDevice{name: prepTestDev1}

		claim := buildPrepClaim(prepTestDev0, prepTestDev1)
		createPrepClaim(t, cs, claim)

		driver := buildPrepDriver(t, cs, dev0, dev1)
		result := prepOne(t, driver, claim)
		require.NoError(t, result.Err)

		require.EqualValues(t, 1, dev0.setupCalls.Load())
		require.EqualValues(t, 1, dev1.setupCalls.Load())
		require.EqualValues(t, 0, dev0.freeCalls.Load())
		require.EqualValues(t, 0, dev1.freeCalls.Load())

		require.Contains(t, driver.allocations, prepTestPodUID)
		require.Len(t, driver.allocations[prepTestPodUID][prepTestClaimUID], 2)

		updated, err := cs.KubernetesFakeClientset.ResourceV1().
			ResourceClaims(prepTestClaimNS).Get(t.Context(), prepTestClaimName, metav1.GetOptions{})
		require.NoError(t, err)
		require.Len(t, updated.Status.Devices, 2)
	})

	t.Run("prepare prepare fails map empty", func(t *testing.T) {
		cs, _ := k8sClient.NewFakeClientset(tlog)
		dev := &trackedDevice{name: prepTestDev0}

		// Claim is NOT created in the API server → UpdateStatus will fail with
		// "not found".
		claim := buildPrepClaim(prepTestDev0)

		driver := buildPrepDriver(t, cs, dev)
		result := prepOne(t, driver, claim)
		require.Error(t, result.Err, "UpdateStatus should fail because claim was not pre-created")

		// no partial entry must be left in the map.
		require.Empty(t, driver.allocations,
			"allocations map must be empty when UpdateStatus fails")
	})

	t.Run("test prepare fails and calls rollback", func(t *testing.T) {
		cs, _ := k8sClient.NewFakeClientset(tlog)
		dev0 := &trackedDevice{name: prepTestDev0}
		dev1 := &trackedDevice{name: prepTestDev1}

		// Claim not in API → UpdateStatus fails after both devices are set up.
		claim := buildPrepClaim(prepTestDev0, prepTestDev1)

		driver := buildPrepDriver(t, cs, dev0, dev1)
		result := prepOne(t, driver, claim)
		require.Error(t, result.Err)

		require.EqualValues(t, 1, dev0.setupCalls.Load())
		require.EqualValues(t, 1, dev1.setupCalls.Load())
		require.EqualValues(t, 1, dev0.freeCalls.Load(), "dev0 must be rolled back")
		require.EqualValues(t, 1, dev1.freeCalls.Load(), "dev1 must be rolled back")
		require.Empty(t, driver.allocations)
	})

	t.Run("test one device succeed, one fails and first one rolled back", func(t *testing.T) {
		cs, _ := k8sClient.NewFakeClientset(tlog)
		dev0 := &trackedDevice{name: prepTestDev0}
		dev1 := &trackedDevice{name: prepTestDev1, setupErr: errors.New("setup exploded")}

		claim := buildPrepClaim(prepTestDev0, prepTestDev1)
		createPrepClaim(t, cs, claim)

		driver := buildPrepDriver(t, cs, dev0, dev1)
		result := prepOne(t, driver, claim)
		require.Error(t, result.Err)
		require.Contains(t, result.Err.Error(), "setup exploded")

		// dev0 succeeded → must be freed by rollback.
		require.EqualValues(t, 1, dev0.setupCalls.Load())
		require.EqualValues(t, 1, dev0.freeCalls.Load(),
			"dev0 must be freed after dev1 Setup fails")

		// dev1 failed → Setup returned error, so Free must NOT be called for it.
		require.EqualValues(t, 1, dev1.setupCalls.Load())
		require.EqualValues(t, 0, dev1.freeCalls.Load(),
			"dev1 Free must not be called because its Setup failed")

		require.Empty(t, driver.allocations)
	})

	t.Run("test one device succeed, one not found and first one rolled back", func(t *testing.T) {
		cs, _ := k8sClient.NewFakeClientset(tlog)
		dev0 := &trackedDevice{name: prepTestDev0}
		// prepTestDev1 is referenced in the claim but NOT registered in the driver.

		claim := buildPrepClaim(prepTestDev0, prepTestDev1)
		createPrepClaim(t, cs, claim)

		driver := buildPrepDriver(t, cs, dev0) // only dev0 registered
		result := prepOne(t, driver, claim)
		require.Error(t, result.Err)
		require.ErrorIs(t, result.Err, errDeviceNotFound)

		// dev0 was set up before the not-found error → must be freed.
		require.EqualValues(t, 1, dev0.setupCalls.Load())
		require.EqualValues(t, 1, dev0.freeCalls.Load(),
			"dev0 must be freed when a later device is not found")

		require.Empty(t, driver.allocations)
	})

	t.Run("test first setup fails and no rollback needed", func(t *testing.T) {
		cs, _ := k8sClient.NewFakeClientset(tlog)
		dev0 := &trackedDevice{name: prepTestDev0, setupErr: errors.New("first device broken")}

		claim := buildPrepClaim(prepTestDev0)
		createPrepClaim(t, cs, claim)

		driver := buildPrepDriver(t, cs, dev0)
		result := prepOne(t, driver, claim)
		require.Error(t, result.Err)

		require.EqualValues(t, 1, dev0.setupCalls.Load())
		require.EqualValues(t, 0, dev0.freeCalls.Load(),
			"Free must not be called for the device whose own Setup failed")
		require.Empty(t, driver.allocations)
	})

	t.Run("test rollback free error returns the original error", func(t *testing.T) {
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
		require.Contains(t, result.Err.Error(), "setup kaboom",
			"original error must propagate even when Free also fails")

		// Free was still attempted on dev0 despite returning an error itself.
		require.EqualValues(t, 1, dev0.freeCalls.Load(),
			"Free must be attempted even when it will fail")

		require.Empty(t, driver.allocations)
	})

	t.Run("test prepare duplicate claim UID is idempotent", func(t *testing.T) {
		cs, _ := k8sClient.NewFakeClientset(tlog)
		dev := &trackedDevice{name: prepTestDev0}
		claim := buildPrepClaim(prepTestDev0)
		createPrepClaim(t, cs, claim)

		driver := buildPrepDriver(t, cs, dev)

		// First call succeeds and sets up the device.
		result := prepOne(t, driver, claim)
		require.NoError(t, result.Err)
		require.EqualValues(t, 1, dev.setupCalls.Load(), "Setup must be called once on first prepare")

		// Update the ResourceVersion so that the second UpdateStatus (if any) works.
		updated, err := cs.KubernetesFakeClientset.ResourceV1().ResourceClaims(prepTestClaimNS).Get(t.Context(), prepTestClaimName, metav1.GetOptions{})
		require.NoError(t, err)
		claim.ResourceVersion = updated.ResourceVersion

		// Second call with the same claim must be idempotent: no error, no re-setup.
		result2 := prepOne(t, driver, claim)
		require.NoError(t, result2.Err)
		require.EqualValues(t, 1, dev.setupCalls.Load(), "Setup must NOT be called again on idempotent retry")
		require.EqualValues(t, 0, dev.freeCalls.Load(), "Free must not be called")
	})

	t.Run("test prepare two claims one pod", func(t *testing.T) {
		cs, _ := k8sClient.NewFakeClientset(tlog)
		dev0 := &trackedDevice{name: prepTestDev0}
		dev1 := &trackedDevice{name: prepTestDev1}

		claim1 := buildPrepClaim(prepTestDev0)
		claim2 := buildPrepClaim2(prepTestDev1)
		createPrepClaim(t, cs, claim1)
		createPrepClaim(t, cs, claim2)

		driver := buildPrepDriver(t, cs, dev0, dev1)

		result1 := prepOne(t, driver, claim1)
		require.NoError(t, result1.Err, "first claim must succeed")

		result2 := prepOne(t, driver, claim2)
		require.NoError(t, result2.Err, "second claim for the same pod must also succeed")

		require.EqualValues(t, 1, dev0.setupCalls.Load(), "dev0 Setup must be called once")
		require.EqualValues(t, 1, dev1.setupCalls.Load(), "dev1 Setup must be called once")

		require.Contains(t, driver.allocations, prepTestPodUID)
		require.Len(t, driver.allocations[prepTestPodUID], 2, "allocations map must have 2 claim entries")
		require.Contains(t, driver.allocations[prepTestPodUID], prepTestClaimUID)
		require.Contains(t, driver.allocations[prepTestPodUID], prepTestClaimUID2)
	})

	t.Run("test prepare cross claim device conflict is not allowed", func(t *testing.T) {
		cs, _ := k8sClient.NewFakeClientset(tlog)
		dev := &trackedDevice{name: prepTestDev0}

		// Both claims request the same device.
		claim1 := buildPrepClaim(prepTestDev0)
		claim2 := buildPrepClaim2(prepTestDev0)
		createPrepClaim(t, cs, claim1)
		createPrepClaim(t, cs, claim2)

		driver := buildPrepDriver(t, cs, dev)

		result1 := prepOne(t, driver, claim1)
		require.NoError(t, result1.Err, "first claim must succeed")

		result2 := prepOne(t, driver, claim2)
		require.Error(t, result2.Err, "second claim requesting the same device must be rejected")
		require.Contains(t, result2.Err.Error(), prepTestDev0)

		// Setup must have been called only once (by the first claim).
		require.EqualValues(t, 1, dev.setupCalls.Load(), "Setup must not be called for the conflicting claim")

		// The pod entry must only contain the first claim.
		require.Contains(t, driver.allocations, prepTestPodUID)
		require.Len(t, driver.allocations[prepTestPodUID], 1)
		require.Contains(t, driver.allocations[prepTestPodUID], prepTestClaimUID)
	})

	t.Run("test invalid pod ifname is not set up", func(t *testing.T) {
		cs, _ := k8sClient.NewFakeClientset(tlog)
		dev := &trackedDevice{name: prepTestDev0}

		rawParam, _ := json.Marshal(map[string]string{
			"podIfName": "this-name-is-way-too-long-for-linux",
		})
		claim := buildPrepClaim(prepTestDev0)
		claim.Status.Allocation.Devices.Config[0].Opaque.Parameters = runtime.RawExtension{Raw: rawParam}
		createPrepClaim(t, cs, claim)

		driver := buildPrepDriver(t, cs, dev)
		result := prepOne(t, driver, claim)
		require.Error(t, result.Err)

		require.EqualValues(t, 0, dev.setupCalls.Load(),
			"Setup must not be called when podIfName validation fails")
		require.Empty(t, driver.allocations)
	})

	t.Run("wrong reservedFor length in claim, we only allow one claim consumer", func(t *testing.T) {
		cs, _ := k8sClient.NewFakeClientset(tlog)
		dev := &trackedDevice{name: prepTestDev0}

		claim := buildPrepClaim(prepTestDev0)
		claim.Status.ReservedFor = append(claim.Status.ReservedFor,
			resourceapi.ResourceClaimConsumerReference{Resource: "pods", Name: "other", UID: "cccc"})
		createPrepClaim(t, cs, claim)

		driver := buildPrepDriver(t, cs, dev)
		result := prepOne(t, driver, claim)
		require.Error(t, result.Err)
		require.ErrorIs(t, result.Err, errUnexpectedInput)
		require.EqualValues(t, 0, dev.setupCalls.Load())
		require.Empty(t, driver.allocations)
	})

	t.Run("generated claim name from template is prepared correctly", func(t *testing.T) {
		cs, _ := k8sClient.NewFakeClientset(tlog)
		dev := &trackedDevice{name: prepTestDev0}
		claim := buildGeneratedPrepClaim(prepTestDev0)
		createPrepClaim(t, cs, claim)

		driver := buildPrepDriver(t, cs, dev)
		result := prepOne(t, driver, claim)
		require.NoError(t, result.Err)
		require.EqualValues(t, 1, dev.setupCalls.Load())
		require.Contains(t, driver.allocations, prepTestPodUID)
	})
}

func TestUnprepare(t *testing.T) {
	tlog := hivetest.Logger(t)

	t.Run("test removes allocations and calls free", func(t *testing.T) {
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
		require.NoError(t, releaseResults[prepTestClaimUID])

		require.Empty(t, driver.allocations,
			"allocations map must be empty after unprepare")
		require.EqualValues(t, 1, dev.freeCalls.Load(), "Free must be called once on unprepare")
	})

	t.Run("multiple devices all are freed", func(t *testing.T) {
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

		require.EqualValues(t, 1, dev0.freeCalls.Load(), "dev0 must be freed")
		require.EqualValues(t, 1, dev1.freeCalls.Load(), "dev1 must be freed")
		require.Empty(t, driver.allocations)
	})

	t.Run("unknown claim (not allocated) does not error out", func(t *testing.T) {
		cs, _ := k8sClient.NewFakeClientset(tlog)
		driver := buildPrepDriver(t, cs)

		releaseResults, err := driver.UnprepareResourceClaims(t.Context(),
			[]kubeletplugin.NamespacedObject{namedObject(prepTestClaimNS, "nonexistent", "zzzz")})
		require.NoError(t, err)
		require.NoError(t, releaseResults["zzzz"])
	})

	t.Run("failed prepare step is rolled back and subsequent prepare succeeds", func(t *testing.T) {
		cs, _ := k8sClient.NewFakeClientset(tlog)
		dev := &trackedDevice{name: prepTestDev0}
		claim := buildPrepClaim(prepTestDev0)

		driver := buildPrepDriver(t, cs, dev)

		// First attempt: claim not in API → UpdateStatus fails → rollback.
		result := prepOne(t, driver, claim)
		require.Error(t, result.Err)
		require.Empty(t, driver.allocations, "map must be clean after failed prepare")

		// Now create the claim in the API.
		createPrepClaim(t, cs, claim)

		// Second attempt: should succeed because the map is clean
		// (no "allocation already exists" guard fires).
		result2 := prepOne(t, driver, claim)
		require.NoError(t, result2.Err, "second prepare must succeed after rollback cleaned up")

		require.Contains(t, driver.allocations, prepTestPodUID)
		require.Len(t, driver.allocations[prepTestPodUID][prepTestClaimUID], 1)

		// Setup called twice (once per attempt), Free called once (rollback of first attempt).
		require.EqualValues(t, 2, dev.setupCalls.Load())
		require.EqualValues(t, 1, dev.freeCalls.Load())
	})
}

// ---------------------------------------------------------------------------
// podForClaim
// ---------------------------------------------------------------------------

// buildPodForClaimDriver builds a *Driver wired to a started hive (so the
// pods informer store is available) and pre-creates the given pod objects in
// the fake API server before the hive starts (so the informer cache picks them
// up during the initial list).
func buildPodForClaimDriver(t *testing.T, pods ...*corev1.Pod) (*Driver, *k8sClient.FakeClientset) {
	t.Helper()
	tlog := hivetest.Logger(t)
	cs, _ := k8sClient.NewFakeClientset(tlog)

	for _, p := range pods {
		_, err := cs.KubernetesFakeClientset.CoreV1().Pods(p.Namespace).
			Create(t.Context(), p, metav1.CreateOptions{})
		require.NoError(t, err)
	}

	driver := buildPrepDriver(t, cs)
	return driver, cs
}

// claimRef builds a ResourceClaimConsumerReference pointing to a pod.
func claimPodRef(name string, uid kubetypes.UID) resourceapi.ResourceClaimConsumerReference {
	return resourceapi.ResourceClaimConsumerReference{
		Resource: "pods",
		Name:     name,
		UID:      uid,
	}
}

func claimInNS(ns string) *resourceapi.ResourceClaim {
	return &resourceapi.ResourceClaim{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: ns,
			Name:      prepTestClaimName,
		},
	}
}

// TestPodForClaim exercises all branches of driver.podForClaim.
func TestPodForClaim(t *testing.T) {
	t.Run("found in store", func(t *testing.T) {
		pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{
			Name:      prepTestPodName,
			Namespace: prepTestClaimNS,
			UID:       prepTestPodUID,
		}}
		driver, _ := buildPodForClaimDriver(t, pod)

		got, err := driver.podForClaim(t.Context(), claimInNS(prepTestClaimNS), claimPodRef(prepTestPodName, prepTestPodUID))
		require.NoError(t, err)
		require.NotNil(t, got)
		require.Equal(t, prepTestPodName, got.Name)
	})

	t.Run("store miss falls back to API", func(t *testing.T) {
		// Driver has empty store; pod is only in the API server.
		driver, cs := buildPodForClaimDriver(t)

		pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{
			Name:      prepTestPodName,
			Namespace: prepTestClaimNS,
			UID:       prepTestPodUID,
		}}
		_, err := cs.KubernetesFakeClientset.CoreV1().Pods(prepTestClaimNS).
			Create(t.Context(), pod, metav1.CreateOptions{})
		require.NoError(t, err)

		got, err := driver.podForClaim(t.Context(), claimInNS(prepTestClaimNS), claimPodRef(prepTestPodName, prepTestPodUID))
		require.NoError(t, err)
		require.NotNil(t, got)
		require.Equal(t, prepTestPodName, got.Name)
	})

	t.Run("not found returns nil without error", func(t *testing.T) {
		driver, _ := buildPodForClaimDriver(t) // no pods anywhere

		got, err := driver.podForClaim(t.Context(), claimInNS(prepTestClaimNS), claimPodRef("ghost-pod", "does-not-exist"))
		require.NoError(t, err)
		require.Nil(t, got, "missing pod must return nil, not an error")
	})

	t.Run("non-404 API error is propagated", func(t *testing.T) {
		driver, cs := buildPodForClaimDriver(t)

		boom := k8serrors.NewInternalError(errors.New("etcd unavailable"))
		cs.KubernetesFakeClientset.PrependReactor("get", "pods",
			func(_ k8stesting.Action) (bool, runtime.Object, error) {
				return true, nil, boom
			})

		_, err := driver.podForClaim(t.Context(), claimInNS(prepTestClaimNS), claimPodRef("unreachable-pod", "uid-xyz"))
		require.Error(t, err)
		require.True(t, k8serrors.IsInternalError(err) || errors.As(err, new(*k8serrors.StatusError)),
			"error must propagate the API server error, got: %v", err)
	})

	t.Run("wrong resource type returns error without hitting store or API", func(t *testing.T) {
		driver, _ := buildPodForClaimDriver(t)

		ref := resourceapi.ResourceClaimConsumerReference{
			Resource: "jobs", // not "pods"
			Name:     "some-job",
			UID:      "uid-job",
		}
		_, err := driver.podForClaim(t.Context(), claimInNS(prepTestClaimNS), ref)
		require.Error(t, err)
		require.Contains(t, err.Error(), "unsupported resource")
	})
}
