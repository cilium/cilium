// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package networkdriver

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path"
	"slices"

	corev1 "k8s.io/api/core/v1"
	resourceapi "k8s.io/api/resource/v1"
	k8sErrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	kube_types "k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/dynamic-resource-allocation/kubeletplugin"

	"github.com/cilium/cilium/pkg/k8s/resource"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/networkdriver/types"
	node_types "github.com/cilium/cilium/pkg/node/types"
	"github.com/cilium/cilium/pkg/time"
)

func (driver *Driver) startDRA(ctx context.Context) error {
	driver.logger.DebugContext(
		ctx, "starting driver",
		logfields.DriverName, driver.config.DriverName,
	)

	// create path for our driver plugin socket.
	if err := os.MkdirAll(driverPluginPath(driver.config.DriverName), 0750); err != nil {
		return fmt.Errorf("failed to create plugin path %s: %w", driverPluginPath(driver.config.DriverName), err)
	}

	pluginOpts := []kubeletplugin.Option{
		kubeletplugin.DriverName(driver.config.DriverName),
		kubeletplugin.NodeName(node_types.GetName()),
		kubeletplugin.KubeClient(driver.kubeClient),
	}

	p, err := kubeletplugin.Start(ctx, driver, pluginOpts...)
	if err != nil {
		return err
	}

	driver.draPlugin = p

	err = wait.PollUntilContextTimeout(
		ctx, time.Duration(driver.config.DraRegistrationRetryIntervalSeconds)*time.Second,
		time.Duration(driver.config.DraRegistrationTimeoutSeconds)*time.Second, true,
		func(context.Context) (bool, error) {
			registrationStatus := driver.draPlugin.RegistrationStatus()
			if registrationStatus == nil {
				return false, nil
			}

			driver.logger.DebugContext(
				ctx, "DRA registration status",
				logfields.Status, registrationStatus,
			)

			return registrationStatus.PluginRegistered, nil
		})

	if err != nil {
		return fmt.Errorf("DRA plugin registration failed: %w", err)
	}

	driver.logger.DebugContext(ctx,
		"DRA plugin registration successful",
		logfields.DriverName, driver.config.DriverName,
	)

	return nil
}

// HandleError logs out error messages from kubelet.
func (d *Driver) HandleError(ctx context.Context, err error, msg string) {
	d.logger.ErrorContext(
		ctx, "HandleError called:",
		logfields.Error, err,
		logfields.Message, msg,
	)
}

// PrepareResourceClaims gets called when we have a request to allocate a resource claim. we also need to have a way to remember
// the allocations elsewhere so allocation state persist across restarts in the plugin.
func (driver *Driver) PrepareResourceClaims(ctx context.Context, claims []*resourceapi.ResourceClaim) (result map[kube_types.UID]kubeletplugin.PrepareResult, err error) {
	driver.logger.DebugContext(ctx, fmt.Sprintf("PrepareResourceClaims called with %d claims", len(claims)))

	result = make(map[kube_types.UID]kubeletplugin.PrepareResult)

	err = driver.withLock(func() error {
		for _, c := range claims {
			l := driver.logger.With(
				logfields.K8sNamespace, c.Namespace,
				logfields.UID, c.UID,
				logfields.Name, c.Name,
			)
			result[c.UID] = driver.prepareResourceClaim(ctx, c)

			l.DebugContext(ctx, "allocation for claim",
				logfields.Result, result[c.UID],
			)
		}

		return nil
	})

	return result, err
}

// UnprepareResourceClaims gets called whenever we have a request to deallocate a resource claim. ex: pod goes away.
func (driver *Driver) UnprepareResourceClaims(ctx context.Context, claims []kubeletplugin.NamespacedObject) (result map[kube_types.UID]error, err error) {
	driver.logger.DebugContext(ctx, fmt.Sprintf("UnprepareResourceClaims called with %d claims", len(claims)))

	result = make(map[kube_types.UID]error, len(claims))

	err = driver.withLock(func() error {
		for _, c := range claims {
			err := driver.unprepareResourceClaim(ctx, c)
			if err != nil {
				driver.logger.ErrorContext(
					ctx, "failed to free resources for claim",
					logfields.Name, c.Name,
					logfields.K8sNamespace, c.Namespace,
					logfields.UID, string(c.UID),
					logfields.Error, err,
				)
			} else {
				driver.logger.DebugContext(
					ctx, "freed resources for claim",
					logfields.Name, c.Name,
					logfields.K8sNamespace, c.Namespace,
					logfields.UID, string(c.UID),
				)
			}
			result[c.UID] = err
		}

		return nil
	})

	return result, err
}

// unprepareResourceClaim removes an allocation and frees up the device.
func (d *Driver) unprepareResourceClaim(ctx context.Context, claim kubeletplugin.NamespacedObject) error {
	var errs []error
	var found bool

	for pod, alloc := range d.allocations {
		devices, ok := alloc[claim.UID]

		if ok {
			found = true
			for _, dev := range devices {
				if err := dev.Device.Free(dev.Config); err != nil {
					errs = append(errs, err)
				}
			}
		}

		if found {
			delete(alloc, claim.UID)
			// see if pod ended up without any allocations.
			// clean it up if we just removed the last one.
			if len(alloc) == 0 {
				delete(d.allocations, pod)
			}

			break
		}
	}

	if !found {
		d.logger.DebugContext(
			ctx, "no allocation found for claim",
			logfields.UID, claim.UID,
			logfields.K8sNamespace, claim.Namespace,
			logfields.Name, claim.Name,
		)
	}

	return errors.Join(errs...)
}

func (driver *Driver) prepareResourceClaim(ctx context.Context, claim *resourceapi.ResourceClaim) kubeletplugin.PrepareResult {
	if len(claim.Status.ReservedFor) != 1 {
		return kubeletplugin.PrepareResult{
			Err: fmt.Errorf("%w: Status.ReservedFor field has more than one entry", errUnexpectedInput),
		}
	}

	pod := claim.Status.ReservedFor[0]

	// Reject devices that are already claimed by a *different* claim for this pod.
	if dev := driver.conflictingDeviceForPod(pod.UID, claim.UID, claim.Status.Allocation.Devices.Results); dev != "" {
		return kubeletplugin.PrepareResult{
			Err: fmt.Errorf("device %s is already allocated for pod %s by another claim", dev, pod.Name),
		}
	}

	deviceClaimConfigs, err := driver.deviceClaimConfigs(ctx, claim)
	if err != nil {
		return kubeletplugin.PrepareResult{Err: err}
	}

	if err := validatePodIfNames(claim, deviceClaimConfigs); err != nil {
		return kubeletplugin.PrepareResult{Err: err}
	}

	// Precompute what is already done so retries skip completed work.
	state := driver.newClaimPrepState(pod, claim)

	var (
		alloc         []allocation
		devicesStatus []resourceapi.AllocatedDeviceStatus
		rollback      bool
	)

	// On any failure after one or more devices were newly set up in this
	// invocation, free those devices. Reused devices (recorded in state) belong
	// to prior successful prepares and are skipped. The device that triggered a
	// failure inside prepareClaimDevice has already rolled itself back and is not
	// present in alloc, so it is not freed twice.
	defer func() {
		if !rollback {
			return
		}
		for _, a := range alloc {
			if _, reused := state.existingByDevice[a.Device.IfName()]; reused {
				continue
			}
			driver.rollbackDevice(a)
		}
	}()

	for _, result := range claim.Status.Allocation.Devices.Results {
		cfg := deviceClaimConfigs[result.Request] // zero-value DeviceConfig if no opaque config present

		deviceAlloc, status, devErr := driver.prepareClaimDevice(ctx, claim, result, cfg, state)
		if devErr != nil {
			rollback = true
			return kubeletplugin.PrepareResult{Err: devErr}
		}

		alloc = append(alloc, deviceAlloc)
		if status != nil {
			devicesStatus = append(devicesStatus, *status)
		}
	}

	// Persist any new device status entries to Kubernetes before committing to
	// memory. Skip the API call when there is nothing new to write (full
	// idempotent retry where all status entries were already present). If
	// UpdateStatus fails we roll back the devices set up in this invocation so the
	// next PrepareResourceClaims call can start fresh.
	if len(devicesStatus) > 0 {
		newClaim := claim.DeepCopy()
		newClaim.Status.Devices = append(newClaim.Status.Devices, devicesStatus...)

		if _, updateErr := driver.kubeClient.ResourceV1().ResourceClaims(claim.Namespace).UpdateStatus(ctx, newClaim, metav1.UpdateOptions{}); updateErr != nil {
			rollback = true
			return kubeletplugin.PrepareResult{
				Err: fmt.Errorf("failed to update claim %s status: %w", path.Join(claim.Namespace, claim.Name), updateErr),
			}
		}
	}

	driver.commitAllocation(pod.UID, claim.UID, alloc)

	// we dont need to return anything here.
	return kubeletplugin.PrepareResult{}
}

func (driver *Driver) deviceClaimConfigs(ctx context.Context, claim *resourceapi.ResourceClaim) (map[string]types.DeviceConfig, error) {
	devicesCfg := map[string]types.DeviceConfig{}
	for _, cfg := range claim.Status.Allocation.Devices.Config {
		if cfg.Opaque != nil && cfg.Opaque.Parameters.Raw != nil {
			c := types.DeviceConfig{}
			if err := json.Unmarshal(cfg.Opaque.Parameters.Raw, &c); err != nil {
				driver.logger.ErrorContext(
					ctx, "failed to parse config",
					logfields.Request, cfg.Requests,
					logfields.Params, cfg.Opaque.Parameters,
					logfields.Error, err,
				)
				return nil, fmt.Errorf("failed to unmarshal config for %s: %w", path.Join(claim.Namespace, claim.Name), err)
			}
			for _, request := range cfg.Requests {
				devicesCfg[request] = c
			}
		}
	}
	return devicesCfg, nil
}

func (driver *Driver) podForClaim(ctx context.Context, claim *resourceapi.ResourceClaim, podRef resourceapi.ResourceClaimConsumerReference) (*corev1.Pod, error) {
	if podRef.Resource != "pods" {
		return nil, fmt.Errorf("claim %s is reserved for unsupported resource %s", path.Join(claim.Namespace, claim.Name), podRef.Resource)
	}

	podStore, err := driver.pods.Store(ctx)
	if err == nil {
		pod, exists, err := podStore.GetByKey(resource.Key{Namespace: claim.Namespace, Name: podRef.Name})
		if err != nil {
			return nil, fmt.Errorf("failed to get pod %s/%s from store: %w", claim.Namespace, podRef.Name, err)
		}
		if exists {
			return pod, nil
		}
	}

	driver.logger.DebugContext(ctx, "unable to get pod from store, falling back to kubernetes client",
		logfields.K8sNamespace, claim.Namespace,
		logfields.Name, claim.Name,
		logfields.K8sPodName, podRef.Name,
		logfields.Error, err,
	)

	pod, err := driver.kubeClient.CoreV1().Pods(claim.Namespace).Get(ctx, podRef.Name, metav1.GetOptions{})
	if k8sErrors.IsNotFound(err) {
		driver.logger.DebugContext(ctx, "pod for claim not found, skipping pod annotations",
			logfields.K8sNamespace, claim.Namespace,
			logfields.Name, claim.Name,
			logfields.K8sPodName, podRef.Name,
		)
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get pod %s/%s for claim %s: %w", claim.Namespace, podRef.Name, path.Join(claim.Namespace, claim.Name), err)
	}

	return pod, nil
}

// claimPrepState holds the precomputed lookups used to make prepareResourceClaim
// idempotent across retries.
type claimPrepState struct {
	// devices already set up for this exact (pod, claim), keyed by ifname.
	existingByDevice map[string]allocation
	// devices that already have a status entry in the claim for this driver.
	existingStatusDevice map[string]struct{}
}

// newClaimPrepState builds the idempotency lookups for a (pod, claim) pair:
// which devices were already set up in memory, and which already have a
// Kubernetes status entry. Both let a retry skip work that already completed.
func (driver *Driver) newClaimPrepState(pod resourceapi.ResourceClaimConsumerReference, claim *resourceapi.ResourceClaim) claimPrepState {
	existingByDevice := make(map[string]allocation)
	for _, a := range driver.allocations[pod.UID][claim.UID] {
		existingByDevice[a.Device.IfName()] = a
	}

	existingStatusDevice := make(map[string]struct{})
	for _, ds := range claim.Status.Devices {
		if ds.Driver == driver.config.DriverName {
			existingStatusDevice[ds.Device] = struct{}{}
		}
	}

	return claimPrepState{
		existingByDevice:     existingByDevice,
		existingStatusDevice: existingStatusDevice,
	}
}

// validatePodIfNames checks that every podIfName in the claim's device configs
// is a valid Linux interface name before any destructive work begins.
func validatePodIfNames(claim *resourceapi.ResourceClaim, deviceClaimConfigs map[string]types.DeviceConfig) error {
	for request, cfg := range deviceClaimConfigs {
		if err := types.ValidateInterfaceName(cfg.PodIfName); err != nil {
			return fmt.Errorf("invalid podIfName in request %s for claim %s: %w",
				request, path.Join(claim.Namespace, claim.Name), err)
		}
	}
	return nil
}

// rollbackDevice undoes the setup of a single device: it frees the device and
// releases any pool-allocated addresses. Failures are logged rather than
// returned, and the call is a safe no-op when there is nothing to undo — a
// zero-value allocation (no device set up) is ignored, and releaseAddrs already
// no-ops for configs without a pool. This lets every error path roll back
// unconditionally without first checking whether work was actually done.
func (driver *Driver) rollbackDevice(a allocation) {
	if a.Device == nil {
		// Nothing was set up for this allocation; nothing to roll back.
		return
	}
	if err := a.Device.Free(a.Config); err != nil {
		driver.logger.Warn("failed to free device during rollback",
			logfields.Device, a.Device.IfName(),
			logfields.Error, err,
		)
	}
}

// prepareClaimDevice processes a single device result of a claim. It returns the
// resulting allocation and the status entry to persist (nil when the device was
// already reflected in the claim status on an idempotent retry).
//
// Any error after the device has been set up rolls back that device in place,
// so the caller never receives a half-prepared device. The idempotent-reuse
// path returns before any setup happens and therefore never rolls back: a
// reused device belongs to a prior successful prepare and must not be freed.
func (driver *Driver) prepareClaimDevice(
	ctx context.Context,
	claim *resourceapi.ResourceClaim,
	result resourceapi.DeviceRequestAllocationResult,
	cfg types.DeviceConfig,
	state claimPrepState,
) (alloc allocation, status *resourceapi.AllocatedDeviceStatus, err error) {
	claimRef := path.Join(claim.Namespace, claim.Name)

	// Idempotency: reuse a device already set up for this (pod, claim) instead
	// of setting it up again. This returns before any setup, so the rollback
	// below is never armed for a reused device.
	if reused, reuseStatus, reuseErr := driver.reuseAllocatedDevice(claim, result, state); reuseErr != nil {
		return allocation{}, nil, reuseErr
	} else if reused != nil {
		return *reused, reuseStatus, nil
	}

	// New device: set it up. prepareDeviceAllocation releases its own addresses
	// if it fails before/at Setup, so nothing was set up on this error path.
	alloc, err = driver.prepareDeviceAllocation(ctx, claimRef, result, cfg)
	if err != nil {
		driver.logger.ErrorContext(ctx, "failed to prepare device allocation",
			logfields.Device, result.Device,
			logfields.Error, err,
		)
		return allocation{}, nil, fmt.Errorf("failed to prepare device %s for claim %s: %w", result.Device, claimRef, err)
	}

	// From here the device is set up: any error must free it. rollbackDevice is
	// a no-op when err is nil.
	defer func() {
		if err != nil {
			driver.rollbackDevice(alloc)
		}
	}()

	built, err := driver.buildDeviceStatus(claim, result, alloc)
	if err != nil {
		driver.logger.ErrorContext(ctx, "failed to serialize device",
			logfields.Device, alloc.Device.IfName(),
			logfields.Config, alloc.Config,
			logfields.Error, err,
		)
		return allocation{}, nil, fmt.Errorf("failed to serialize device %s for claim %s: %w", alloc.Device.IfName(), claimRef, err)
	}

	return alloc, &built, nil
}

func (driver *Driver) prepareDeviceAllocation(ctx context.Context, claim string, result resourceapi.DeviceRequestAllocationResult, cfg types.DeviceConfig) (allocation, error) {
	alloc := allocation{Config: cfg}

	var found bool
	for mgr, devices := range driver.devices {
		if i := slices.IndexFunc(devices, func(dev types.Device) bool {
			return dev.IfName() == result.Device
		}); i >= 0 {
			alloc.Manager = mgr
			alloc.Device = devices[i]
			found = true
			break
		}
	}
	if !found {
		return alloc, fmt.Errorf("%w with ifname %s for %s", errDeviceNotFound, result.Device, claim)
	}

	if err := alloc.Device.Setup(alloc.Config); err != nil {
		driver.logger.ErrorContext(ctx, "failed to set up device",
			logfields.Device, alloc.Device.IfName(),
			logfields.Config, alloc.Config,
			logfields.Error, err,
		)

		return alloc, fmt.Errorf("%w for ifname %s on %s", err, alloc.Device.IfName(), claim)
	}

	return alloc, nil
}

// reuseAllocatedDevice implements the idempotency path for a single device
// result. If the device was already set up for this (pod, claim) — recorded in
// state.existingByDevice — it returns the stored allocation so the caller can
// skip the setup step entirely.
//
// It additionally returns a device status entry when the in-memory allocation
// exists but its Kubernetes status entry does not (e.g. the driver crashed
// between Device.Setup and UpdateStatus): the caller appends it so the missing
// status is rewritten on this retry. When the status entry is already present
// the returned status is nil and nothing needs to be rewritten.
//
// A nil allocation means the device was not previously set up and the caller
// must run the full setup path. Errors are not wrapped into the rollback flow:
// a reused device belongs to a prior successful prepare and must never be freed
// here.
func (driver *Driver) reuseAllocatedDevice(
	claim *resourceapi.ResourceClaim,
	result resourceapi.DeviceRequestAllocationResult,
	state claimPrepState,
) (*allocation, *resourceapi.AllocatedDeviceStatus, error) {
	existing, alreadyDone := state.existingByDevice[result.Device]
	if !alreadyDone {
		return nil, nil, nil
	}

	if _, statusPresent := state.existingStatusDevice[result.Device]; statusPresent {
		return &existing, nil, nil
	}

	status, err := driver.buildDeviceStatus(claim, result, existing)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to serialize already-set-up device %s for claim %s: %w",
			result.Device, path.Join(claim.Namespace, claim.Name), err)
	}

	return &existing, &status, nil
}

// buildDeviceStatus serializes a fully set-up device allocation into the
// AllocatedDeviceStatus that is written to ResourceClaim.Status.Devices.
func (driver *Driver) buildDeviceStatus(
	claim *resourceapi.ResourceClaim,
	result resourceapi.DeviceRequestAllocationResult,
	a allocation,
) (resourceapi.AllocatedDeviceStatus, error) {
	rawDev, err := serializeDevice(a)
	if err != nil {
		return resourceapi.AllocatedDeviceStatus{}, err
	}

	ifName := a.Device.IfName()
	if a.Config.PodIfName != "" {
		ifName = a.Config.PodIfName
	}

	return resourceapi.AllocatedDeviceStatus{
		Driver:     driver.config.DriverName,
		Pool:       result.Pool,
		Device:     result.Device,
		Conditions: []metav1.Condition{conditionReady(claim)},
		Data:       &runtime.RawExtension{Raw: rawDev},
		NetworkData: &resourceapi.NetworkDeviceData{
			InterfaceName: ifName,
		},
	}, nil
}

// conflictingDeviceForPod returns the ifname of the first device that is
// already allocated to podUID by a claim other than skipClaimUID, or "" if
// there is no conflict. The check is intentionally skipped for skipClaimUID so
// that re-preparing an existing claim (idempotent retry) is not rejected.
func (driver *Driver) conflictingDeviceForPod(podUID kube_types.UID, skipClaimUID kube_types.UID, results []resourceapi.DeviceRequestAllocationResult) string {
	for claimUID, allocs := range driver.allocations[podUID] {
		if claimUID == skipClaimUID {
			continue
		}
		for _, result := range results {
			for _, a := range allocs {
				if a.Device.IfName() == result.Device {
					return result.Device
				}
			}
		}
	}
	return ""
}

// commitAllocation stores allocs under driver.allocations[podUID][claimUID],
// creating the inner map if this is the first claim for the pod.
func (driver *Driver) commitAllocation(podUID, claimUID kube_types.UID, allocs []allocation) {
	if _, exists := driver.allocations[podUID]; !exists {
		driver.allocations[podUID] = make(map[kube_types.UID][]allocation)
	}
	driver.allocations[podUID][claimUID] = allocs
}

func conditionReady(claim *resourceapi.ResourceClaim) metav1.Condition {
	return metav1.Condition{
		Type:               "Ready",
		Status:             metav1.ConditionTrue,
		Reason:             "Ready",
		Message:            "Device is ready",
		ObservedGeneration: claim.GetGeneration(),
		LastTransitionTime: metav1.NewTime(time.Now()),
	}
}

func serializeDevice(a allocation) ([]byte, error) {
	data, err := a.Device.MarshalBinary()
	if err != nil {
		return nil, err
	}

	return json.Marshal(types.SerializedDevice{
		Manager: a.Manager,
		Dev:     data,
		Config:  a.Config,
	})
}

func deserializeDevice(data []byte) (types.DeviceManagerType, json.RawMessage, types.DeviceConfig, error) {
	var dev types.SerializedDevice

	if err := json.Unmarshal(data, &dev); err != nil {
		return types.DeviceManagerTypeUnknown, nil, types.DeviceConfig{}, err
	}

	return dev.Manager, dev.Dev, dev.Config, nil
}
