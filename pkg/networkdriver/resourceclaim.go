// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package networkdriver

import (
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"path"

	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/networkdriver/types"

	resourceapi "k8s.io/api/resource/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	kube_types "k8s.io/apimachinery/pkg/types"
	"k8s.io/dynamic-resource-allocation/kubeletplugin"
)

// validatedClaim is the output of pass 1 for a single claim.
// configs is nil for claims that are already handled (idempotent or
// restorable from status) and non-nil for claims that need fresh device setup.
type validatedClaim struct {
	claim   *resourceapi.ResourceClaim
	pod     resourceapi.ResourceClaimConsumerReference
	configs map[string]types.DeviceConfig // nil → skip setup in pass 2
}

func (v validatedClaim) needsSetup() bool { return v.configs != nil }

// validateBatch is pass 1: it validates every claim in the batch without
// touching any devices or writing to driver.allocations.
//
// It detects all errors upfront so pass 2 only runs when the whole batch is
// known to be clean.  Cross-claim collision checks cover both existing
// allocations in driver.allocations and claims earlier in the same batch that
// have not yet been committed.
func (driver *Driver) validateBatch(ctx context.Context, claims []*resourceapi.ResourceClaim) ([]validatedClaim, map[kube_types.UID]error) {
	errs := map[kube_types.UID]error{}
	validated := make([]validatedClaim, 0, len(claims))

	// batchDevices and batchPodIfNames accumulate the devices and interface
	// names claimed by earlier entries in this batch.  They are needed because
	// those claims are not in driver.allocations yet.
	batchDevices := map[string]struct{}{}
	batchPodIfNames := map[string]struct{}{}

	for _, claim := range claims {
		v, err := driver.validateOneClaim(ctx, claim, batchDevices, batchPodIfNames)
		if err != nil {
			errs[claim.UID] = err
			continue
		}

		validated = append(validated, v)

		// Register this claim's resources as pending for subsequent claims.
		for _, result := range claim.Status.Allocation.Devices.Results {
			batchDevices[result.Device] = struct{}{}
		}
		if v.needsSetup() {
			for _, cfg := range v.configs {
				if cfg.PodIfName != "" {
					batchPodIfNames[cfg.PodIfName] = struct{}{}
				}
			}
		}
	}

	if len(errs) > 0 {
		return nil, errs
	}

	return validated, nil
}

// validateOneClaim validates a single claim against existing allocations and
// the in-progress batch state (batchDevices, batchPodIfNames).
// skips claims that are already setup, signals that a restre is needed
// if the local state is inconsistent with the kube api state, and lastly
// calls parseAndValidateConfigs that ensures the claim configurations are valid.
func (driver *Driver) validateOneClaim(
	ctx context.Context,
	claim *resourceapi.ResourceClaim,
	batchDevices map[string]struct{},
	batchPodIfNames map[string]struct{},
) (validatedClaim, error) {
	pod, err := claimPod(claim)
	if err != nil {
		return validatedClaim{}, err
	}

	// Idempotency: already committed in a previous call.
	if driver.isPrepared(pod.UID, claim.UID) {
		driver.logger.DebugContext(ctx, "claim already prepared, skipping",
			logfields.UID, claim.UID,
			logfields.Name, claim.Name,
			logfields.K8sNamespace, claim.Namespace,
		)

		return validatedClaim{claim: claim, pod: pod}, nil
	}

	// Crash-recovery: UpdateStatus succeeded previously but driver.allocations
	// was not written.  Pass 2 will restore without calling Setup again.
	if driver.hasStatusDevices(claim) {
		driver.logger.InfoContext(ctx, "claim has existing status devices, will restore",
			logfields.Name, claim.Name,
			logfields.K8sNamespace, claim.Namespace,
			logfields.UID, claim.UID,
		)

		return validatedClaim{claim: claim, pod: pod}, nil
	}

	configs, err := driver.parseAndValidateConfigs(ctx, claim, pod.UID, batchDevices, batchPodIfNames)
	if err != nil {
		return validatedClaim{}, err
	}

	return validatedClaim{claim: claim, pod: pod, configs: configs}, nil
}

// hasStatusDevices reports whether the claim already has status devices written
// by this driver (crash-before-map-write indicator), without touching state.
func (driver *Driver) hasStatusDevices(claim *resourceapi.ResourceClaim) bool {
	for _, devStatus := range claim.Status.Devices {
		if devStatus.Driver == driver.config.DriverName {
			return true
		}
	}

	return false
}

// executeClaim is pass 2 for a single validated claim.  It either restores
// state from an existing claim status or runs full device setup, then persists
// to Kubernetes and commits to driver.allocations.
func (driver *Driver) executeClaim(ctx context.Context, v validatedClaim) kubeletplugin.PrepareResult {
	// Already committed (idempotent) — nothing to do.
	if driver.isPrepared(v.pod.UID, v.claim.UID) {
		return kubeletplugin.PrepareResult{}
	}

	// Crash-recovery path: restore from status, no Setup needed.
	if !v.needsSetup() {
		if !driver.tryRestoreFromStatus(ctx, v.claim, v.pod.UID) {
			// Should not happen: validateBatch confirmed status devices exist.
			return kubeletplugin.PrepareResult{Err: errRestoreClaimFailed}
		}

		return kubeletplugin.PrepareResult{}
	}

	// Fresh setup path.
	allocs, statuses, err := driver.setupDevices(ctx, v.claim, v.configs)
	if err != nil {
		return kubeletplugin.PrepareResult{Err: err}
	}

	newClaim := v.claim.DeepCopy()
	newClaim.Status.Devices = append(newClaim.Status.Devices, statuses...)
	if _, err := driver.kubeClient.ResourceV1().ResourceClaims(v.claim.Namespace).
		UpdateStatus(ctx, newClaim, metav1.UpdateOptions{}); err != nil {
		// failed to update status, revert the devices we already set up
		for _, a := range allocs {
			if err := a.Device.Free(a.Config); err != nil {
				driver.logger.Warn("failed to free device after UpdateStatus failure",
					logfields.Device, a.Device.IfName(),
					logfields.Error, err,
				)
			}

			if err := driver.releaseAddrs(a.Config); err != nil {
				driver.logger.Warn("failed to release addresses after UpdateStatus failure",
					logfields.Device, a.Device.IfName(),
					logfields.Error, err,
				)
			}
		}

		return kubeletplugin.PrepareResult{
			Err: fmt.Errorf("%w %w", errClaimUpdateStatusFailed, err),
		}
	}

	driver.commitAllocation(v.pod.UID, v.claim.UID, allocs)
	return kubeletplugin.PrepareResult{}
}

// claimPod extracts and validates the pod consumer reference from a claim.
// we currently only support:
// - 1 consumer reference
// - consumer is a pod
// - claim allocation != nil (that means, scheduler filled the Status.Allocation field for the claim)
func claimPod(claim *resourceapi.ResourceClaim) (resourceapi.ResourceClaimConsumerReference, error) {
	if len(claim.Status.ReservedFor) != 1 {
		return resourceapi.ResourceClaimConsumerReference{},
			fmt.Errorf("%w: Status.ReservedFor field has more than one entry", errUnexpectedInput)
	}

	pod := claim.Status.ReservedFor[0]
	if pod.Resource != "pods" {
		return resourceapi.ResourceClaimConsumerReference{},
			fmt.Errorf("%w: unsupported consumer resource %q, only \"pods\" is supported", errUnexpectedInput, pod.Resource)
	}

	if claim.Status.Allocation == nil {
		return resourceapi.ResourceClaimConsumerReference{},
			fmt.Errorf("%w: claim %s has no allocation", errUnexpectedInput, path.Join(claim.Namespace, claim.Name))
	}

	return pod, nil
}

// isPrepared reports whether the given claim has already been committed to
// the in-memory allocations map (idempotency check).
func (driver *Driver) isPrepared(podUID, claimUID kube_types.UID) bool {
	if claimAllocs, ok := driver.allocations[podUID]; ok {
		_, exists := claimAllocs[claimUID]
		return exists
	}

	return false
}

// tryRestoreFromStatus attempts to recover from a crash-before-map-write
// scenario: UpdateStatus succeeded in a previous run so Status.Devices is
// populated, but the driver crashed before it could write to
// driver.allocations.  Returns true when all devices are fully restored and
// the caller can return success without re-running Setup.
func (driver *Driver) tryRestoreFromStatus(ctx context.Context, claim *resourceapi.ResourceClaim, podUID kube_types.UID) bool {
	var restored []allocation

	for _, devStatus := range claim.Status.Devices {
		if devStatus.Driver != driver.config.DriverName {
			continue
		}

		alloc, err := driver.deviceFromClaim(devStatus)
		if err != nil {
			driver.logger.WarnContext(ctx, "failed to restore device from existing claim status, will re-prepare",
				logfields.Name, claim.Name,
				logfields.K8sNamespace, claim.Namespace,
				logfields.Error, err,
			)

			return false
		}

		restored = append(restored, alloc)
	}

	if len(restored) == 0 {
		return false
	}

	driver.commitAllocation(podUID, claim.UID, restored)
	driver.logger.InfoContext(ctx, "restored claim allocation from existing status",
		logfields.Name, claim.Name,
		logfields.K8sNamespace, claim.Namespace,
		logfields.UID, claim.UID,
	)

	return true
}

// parseAndValidateConfigs parses per-request device configs from the claim
// and runs all validation checks before any device Setup is attempted:
//
//   - podIfName format validity
//   - duplicate device names within the claim
//   - duplicate podIfNames within the claim
//   - podIfName and device name collisions against already-allocated claims
//     for the same pod (from driver.allocations)
//   - podIfName and device name collisions against other claims in the same
//     in-progress batch (batchDevices / batchPodIfNames)
func (driver *Driver) parseAndValidateConfigs(
	ctx context.Context,
	claim *resourceapi.ResourceClaim,
	podUID kube_types.UID,
	batchDevices map[string]struct{},
	batchPodIfNames map[string]struct{},
) (map[string]types.DeviceConfig, error) {
	claimKey := path.Join(claim.Namespace, claim.Name)

	// Parse per-request configs from opaque parameters.
	configs := map[string]types.DeviceConfig{}

	for _, cfg := range claim.Status.Allocation.Devices.Config {
		if cfg.Opaque == nil || cfg.Opaque.Parameters.Raw == nil {
			continue
		}

		var c types.DeviceConfig

		if err := json.Unmarshal(cfg.Opaque.Parameters.Raw, &c); err != nil {
			driver.logger.ErrorContext(ctx, "failed to parse config",
				logfields.Request, cfg.Requests,
				logfields.Params, cfg.Opaque.Parameters,
				logfields.Error, err,
			)

			return nil, fmt.Errorf("failed to unmarshal config for %s: %w", claimKey, err)
		}

		for _, request := range cfg.Requests {
			configs[request] = c
		}
	}

	// Validate podIfName format for every request.
	for request, cfg := range configs {
		if err := types.ValidateInterfaceName(cfg.PodIfName); err != nil {
			return nil, fmt.Errorf("invalid podIfName in request %s for claim %s: %w", request, claimKey, err)
		}
	}

	// Within-claim: no device or podIfName may appear twice.
	seenDevices := make(map[string]struct{})
	seenPodIfNames := make(map[string]string) // podIfName → first request that used it

	for _, result := range claim.Status.Allocation.Devices.Results {
		if _, dup := seenDevices[result.Device]; dup {
			return nil, fmt.Errorf("%w: device %q appears more than once in claim %s",
				errUnexpectedInput, result.Device, claimKey)
		}

		seenDevices[result.Device] = struct{}{}

		if cfg := configs[result.Request]; cfg.PodIfName != "" {
			if prev, dup := seenPodIfNames[cfg.PodIfName]; dup {
				return nil, fmt.Errorf("%w: podIfName %q is used by both request %q and %q in claim %s",
					errUnexpectedInput, cfg.PodIfName, prev, result.Request, claimKey)
			}

			seenPodIfNames[cfg.PodIfName] = result.Request
		}
	}

	// Cross-claim: no device or podIfName may already be in use by another
	// claim allocated to the same pod.
	existingAllocs := driver.allocations[podUID]
	for _, existingClaim := range existingAllocs {
		for _, a := range existingClaim {
			for _, result := range claim.Status.Allocation.Devices.Results {
				if a.Device.IfName() == result.Device {
					return nil, fmt.Errorf("%w: device %q is already allocated to pod %s by another claim",
						errUnexpectedInput, result.Device, podUID)
				}
			}

			if a.Config.PodIfName == "" {
				continue
			}

			for _, cfg := range configs {
				if cfg.PodIfName == a.Config.PodIfName {
					return nil, fmt.Errorf("%w: podIfName %q is already used by another claim for pod %s",
						errUnexpectedInput, cfg.PodIfName, podUID)
				}
			}
		}
	}

	// Cross-claim: same checks against other claims in the same in-progress batch
	// (not yet in driver.allocations).
	for _, result := range claim.Status.Allocation.Devices.Results {
		if _, conflict := batchDevices[result.Device]; conflict {
			return nil, fmt.Errorf("%w: device %q is requested by more than one claim in this batch for pod %s",
				errUnexpectedInput, result.Device, podUID)
		}
	}

	for _, cfg := range configs {
		if cfg.PodIfName == "" {
			continue
		}

		if _, conflict := batchPodIfNames[cfg.PodIfName]; conflict {
			return nil, fmt.Errorf("%w: podIfName %q is requested by more than one claim in this batch for pod %s",
				errUnexpectedInput, cfg.PodIfName, podUID)
		}
	}

	return configs, nil
}

// lookupDevice finds the physical device matching deviceName in driver.devices
// and fills a.Device and a.Manager.
func (driver *Driver) lookupDevice(deviceName string, a *allocation) error {
	for mgr, devices := range driver.devices {
		for _, dev := range devices {
			if dev.IfName() == deviceName {
				a.Manager = mgr
				a.Device = dev
				return nil
			}
		}
	}

	return fmt.Errorf("%w with ifname %s", errDeviceNotFound, deviceName)
}

// assignAddrs allocates pool IP addresses into a.Config when static addresses
// are not already present.  It is a no-op when both IPv4 and IPv6 are
// statically configured or the respective IP family is disabled.
func (driver *Driver) assignAddrs(ctx context.Context, deviceName string, a *allocation) error {
	var zeroAddr netip.Addr
	v4Needed := driver.ipv4Enabled && a.Config.IPv4Addr.Addr() == zeroAddr
	v6Needed := driver.ipv6Enabled && a.Config.IPv6Addr.Addr() == zeroAddr

	if a.Config.IPPool == "" {
		return nil
	}

	if !v4Needed && !v6Needed {
		return nil
	}

	v4, v6, err := driver.addrsForDevice(ctx, deviceName, a.Config, v4Needed, v6Needed)
	if err != nil {
		return fmt.Errorf("failed to get IP addresses for device %s: %w", deviceName, err)
	}

	if v4Needed {
		a.Config.IPv4Addr = netip.PrefixFrom(v4, v4.BitLen())
	}

	if v6Needed {
		a.Config.IPv6Addr = netip.PrefixFrom(v6, v6.BitLen())
	}

	return nil
}

// setupOneDevice runs the full per-device pipeline: lookup → assign IPs →
// Setup → serialize.  It is responsible for cleaning up its own partial state
// if any step after IP assignment fails (the caller's rollback handles only
// devices that were fully set up and appended to allocs).
func (driver *Driver) setupOneDevice(
	ctx context.Context,
	claim *resourceapi.ResourceClaim,
	result resourceapi.DeviceRequestAllocationResult,
	config types.DeviceConfig,
) (allocation, resourceapi.AllocatedDeviceStatus, error) {
	a := allocation{Config: config}
	claimKey := path.Join(claim.Namespace, claim.Name)

	if err := driver.lookupDevice(result.Device, &a); err != nil {
		return allocation{}, resourceapi.AllocatedDeviceStatus{},
			fmt.Errorf("%w for claim %s", err, claimKey)
	}

	if err := driver.assignAddrs(ctx, result.Device, &a); err != nil {
		return allocation{}, resourceapi.AllocatedDeviceStatus{},
			fmt.Errorf("%w for claim %s", err, claimKey)
	}

	if err := a.Device.Setup(a.Config); err != nil {
		// IPs were allocated above but this device will not be appended to
		// allocs, so release them here rather than relying on the outer defer.
		if err := driver.releaseAddrs(a.Config); err != nil {
			driver.logger.Warn("failed to release addresses for device whose Setup failed",
				logfields.Device, a.Device.IfName(),
				logfields.Error, err,
			)
		}

		return allocation{}, resourceapi.AllocatedDeviceStatus{},
			fmt.Errorf("failed to set up device %s for claim %s: %w", result.Device, claimKey, err)
	}

	serialized, err := serializeDevice(a)
	if err != nil {
		// Setup succeeded, but serialized failed — free the device and release IPs before returning.
		if err := a.Device.Free(a.Config); err != nil {
			driver.logger.Warn("failed to free device after serialization failure",
				logfields.Device, a.Device.IfName(),
				logfields.Error, err,
			)
		}

		if err := driver.releaseAddrs(a.Config); err != nil {
			driver.logger.Warn("failed to release addresses after serialization failure",
				logfields.Device, a.Device.IfName(),
				logfields.Error, err,
			)
		}

		return allocation{}, resourceapi.AllocatedDeviceStatus{},
			fmt.Errorf("failed to serialize device %s for claim %s: %w", a.Device.IfName(), claimKey, err)
	}

	return a, buildDeviceStatus(driver.config.DriverName, claim, result, a, serialized), nil
}

// buildDeviceStatus constructs the AllocatedDeviceStatus entry for a device
// that has been successfully set up.
func buildDeviceStatus(
	driverName string,
	claim *resourceapi.ResourceClaim,
	result resourceapi.DeviceRequestAllocationResult,
	a allocation,
	serialized []byte,
) resourceapi.AllocatedDeviceStatus {
	var ips []string

	if a.Config.IPv4Addr.IsValid() {
		ips = append(ips, a.Config.IPv4Addr.String())
	}

	if a.Config.IPv6Addr.IsValid() {
		ips = append(ips, a.Config.IPv6Addr.String())
	}

	ifName := a.Device.IfName()
	if a.Config.PodIfName != "" {
		ifName = a.Config.PodIfName
	}

	return resourceapi.AllocatedDeviceStatus{
		Driver:     driverName,
		Pool:       result.Pool,
		Device:     result.Device,
		Conditions: []metav1.Condition{conditionReady(claim)},
		Data:       &runtime.RawExtension{Raw: serialized},
		NetworkData: &resourceapi.NetworkDeviceData{
			InterfaceName: ifName,
			IPs:           ips,
		},
	}
}

// setupDevices iterates over the claim's requested devices and sets each one
// up via setupOneDevice.  On any error the deferred rollback frees all devices
// that were already successfully set up.
func (driver *Driver) setupDevices(
	ctx context.Context,
	claim *resourceapi.ResourceClaim,
	configs map[string]types.DeviceConfig,
) ([]allocation, []resourceapi.AllocatedDeviceStatus, error) {
	var allocs []allocation
	var statuses []resourceapi.AllocatedDeviceStatus
	var err error

	defer func() {
		if err == nil {
			return
		}

		for _, a := range allocs {
			if freeErr := a.Device.Free(a.Config); freeErr != nil {
				driver.logger.Warn("failed to free device during rollback",
					logfields.Device, a.Device.IfName(),
					logfields.Error, freeErr,
				)
			}

			if relErr := driver.releaseAddrs(a.Config); relErr != nil {
				driver.logger.Warn("failed to release addresses during rollback",
					logfields.Device, a.Device.IfName(),
					logfields.Error, relErr,
				)
			}
		}
	}()

	for _, result := range claim.Status.Allocation.Devices.Results {
		var a allocation
		var status resourceapi.AllocatedDeviceStatus

		if a, status, err = driver.setupOneDevice(ctx, claim, result, configs[result.Request]); err != nil {
			return nil, nil, err
		}

		allocs = append(allocs, a)
		statuses = append(statuses, status)
	}

	return allocs, statuses, err
}

// commitAllocation writes the allocation to the in-memory map.
func (driver *Driver) commitAllocation(podUID, claimUID kube_types.UID, allocs []allocation) {
	if driver.allocations[podUID] == nil {
		driver.allocations[podUID] = make(map[kube_types.UID][]allocation)
	}

	driver.allocations[podUID][claimUID] = allocs
}
