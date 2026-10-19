// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package networkdriver

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net/netip"
	"os"
	"path"
	"slices"
	"strings"

	corev1 "k8s.io/api/core/v1"
	resourceapi "k8s.io/api/resource/v1"
	k8sErrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	kube_types "k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/dynamic-resource-allocation/kubeletplugin"
	"k8s.io/dynamic-resource-allocation/resourceclaim"
	draresourceclaim "k8s.io/dynamic-resource-allocation/resourceclaim"
	"k8s.io/utils/ptr"

	"github.com/cilium/cilium/pkg/annotation"
	"github.com/cilium/cilium/pkg/ipam"
	"github.com/cilium/cilium/pkg/k8s/resource"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/networkdriver/types"
	node_types "github.com/cilium/cilium/pkg/node/types"
	"github.com/cilium/cilium/pkg/resiliency"
	"github.com/cilium/cilium/pkg/time"
)

func (driver *Driver) startDRA(ctx context.Context) error {
	driver.logger.InfoContext(
		ctx, "starting DRA plugin",
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

	retryInterval := time.Duration(driver.config.DraRegistrationRetryIntervalSeconds) * time.Second
	attemptTimeout := time.Duration(driver.config.DraRegistrationTimeoutSeconds) * time.Second
	maxAttempts := int(driver.config.DraRegistrationMaxAttempts)

	err := resiliency.Retry(ctx, retryInterval, maxAttempts, func(ctx context.Context, attempt int) (bool, error) {
		p, err := kubeletplugin.Start(ctx, driver, pluginOpts...)
		if err != nil {
			// Fatal: socket or gRPC setup failed; no point retrying.
			return false, err
		}
		driver.draPlugin = p

		// Wait up to attemptTimeout for kubelet to call back and complete registration.
		// Kubelet discovers the plugin via an inotify watch on plugins_registry/. If it
		// misses the CREATE event (e.g. because it was momentarily busy or restarting),
		// stopping the plugin removes the socket, and the next attempt creates a fresh one,
		// re-triggering the inotify event.
		attemptCtx, cancelAttempt := context.WithTimeout(ctx, attemptTimeout)
		pollErr := wait.PollUntilContextTimeout(
			attemptCtx, retryInterval, attemptTimeout, true,
			func(context.Context) (bool, error) {
				status := driver.draPlugin.RegistrationStatus()
				if status == nil {
					return false, nil
				}
				driver.logger.DebugContext(ctx, "DRA registration status",
					logfields.Status, status,
				)
				return status.PluginRegistered, nil
			})
		cancelAttempt()

		if pollErr == nil {
			// Registered — done.
			return true, nil
		}

		// Attempt timed out (or ctx cancelled). Stop the plugin so its sockets are
		// removed; the next attempt will recreate them and retrigger kubelet's watcher.
		driver.draPlugin.Stop()
		driver.draPlugin = nil

		if ctx.Err() != nil {
			return false, ctx.Err()
		}

		driver.logger.WarnContext(ctx,
			"DRA plugin registration attempt timed out, recreating sockets and retrying",
			logfields.DriverName, driver.config.DriverName,
			logfields.Attempt, attempt,
		)
		return false, nil
	})

	if err != nil {
		return fmt.Errorf("DRA plugin registration failed: %w", err)
	}

	driver.logger.InfoContext(ctx,
		"DRA plugin registration successful",
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

// WatchHealthStatus reports device health to the kubelet. The driver does not
// track device health, so it declines the service: the kubelet is told the
// stream is unimplemented and stops watching.
func (d *Driver) WatchHealthStatus(ctx context.Context, reports chan<- kubeletplugin.DeviceHealthReport) error {
	return kubeletplugin.ErrHealthNotSupported
}

// PrepareResourceClaims gets called when we have a request to allocate a resource claim. we also need to have a way to remember
// the allocations elsewhere so allocation state persist across restarts in the plugin.
func (driver *Driver) PrepareResourceClaims(ctx context.Context, claims []*resourceapi.ResourceClaim) (map[kube_types.UID]kubeletplugin.PrepareResult, error) {
	driver.logger.DebugContext(ctx, fmt.Sprintf("PrepareResourceClaims called with %d claims", len(claims)))

	result := make(map[kube_types.UID]kubeletplugin.PrepareResult)

	driver.withLockNoErr(func() {
		for _, c := range claims {
			l := driver.logger.With(
				logfields.K8sNamespace, c.Namespace,
				logfields.UID, c.UID,
				logfields.Name, c.Name,
			)
			claimResult := driver.prepareResourceClaim(ctx, c)
			result[c.UID] = claimResult

			// If there is an error we want to log it here the kubelet won't do it for us.
			// Ref: https://github.com/kubernetes/kubernetes/blob/v1.37.0/pkg/kubelet/cm/dra/manager.go#L425-L436
			if claimResult.Err != nil {
				l.ErrorContext(ctx, "failed to prepare resources for claim",
					logfields.Error, claimResult.Err,
				)
				continue
			}
			l.DebugContext(ctx, "successful allocation for claim",
				logfields.Result, claimResult,
			)
		}
	})

	return result, nil
}

// UnprepareResourceClaims gets called whenever we have a request to deallocate a resource claim. ex: pod goes away.
func (driver *Driver) UnprepareResourceClaims(ctx context.Context, claims []kubeletplugin.NamespacedObject) (map[kube_types.UID]error, error) {
	driver.logger.DebugContext(ctx, fmt.Sprintf("UnprepareResourceClaims called with %d claims", len(claims)))

	result := make(map[kube_types.UID]error, len(claims))

	driver.withLockNoErr(func() {
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
	})

	return result, nil
}

// unprepareResourceClaim removes an allocation and frees up the device.
func (d *Driver) unprepareResourceClaim(ctx context.Context, claim kubeletplugin.NamespacedObject) error {
	// Look up all devices for this claim via the secondary index.
	txn := d.db.ReadTxn()
	var devices []allocation
	for row := range AllocationsByClaimUID(d.allocationTable, txn, claim.UID) {
		if row.PreparedDevice != nil {
			devices = append(devices, allocationFromRow(row))
		}
	}

	if len(devices) == 0 {
		d.logger.DebugContext(
			ctx, "no allocation found for claim",
			logfields.UID, claim.UID,
			logfields.K8sNamespace, claim.Namespace,
			logfields.Name, claim.Name,
		)
		return nil
	}

	var (
		freed []allocation
		errs  []error
	)
	for _, dev := range devices {
		if err := d.cleanupAllocation(dev); err != nil {
			errs = append(errs, fmt.Errorf("failed to release device: %w", err))
			continue
		}
		freed = append(freed, dev)
	}
	// Keep failed allocations so a later unprepare can retry their cleanup.
	d.deleteAllocations(freed)
	return errors.Join(errs...)
}

func (driver *Driver) prepareResourceClaim(ctx context.Context, claim *resourceapi.ResourceClaim) kubeletplugin.PrepareResult {
	if len(claim.Status.ReservedFor) != 1 {
		return kubeletplugin.PrepareResult{
			Err: fmt.Errorf("%w: Status.ReservedFor field has more than one entry", errUnexpectedInput),
		}
	}

	podRef := claim.Status.ReservedFor[0]

	// Reject devices that are already claimed by a *different* claim for this pod.
	if dev := driver.conflictingDeviceForPod(podRef.UID, claim.UID, claim.Status.Allocation.Devices.Results); dev != "" {
		return kubeletplugin.PrepareResult{
			Err: fmt.Errorf("device %s is already allocated for pod %s by another claim", dev, podRef.Name),
		}
	}

	deviceClaimConfigs, err := driver.deviceClaimConfigs(ctx, claim)
	if err != nil {
		return kubeletplugin.PrepareResult{Err: err}
	}

	staticAddrsMap, err := driver.getStaticAddrsForClaim(ctx, claim, podRef)
	if err != nil {
		return kubeletplugin.PrepareResult{Err: err}
	}

	if err := driver.validateConfigs(claim, deviceClaimConfigs, staticAddrsMap); err != nil {
		return kubeletplugin.PrepareResult{Err: err}
	}

	driver.applyStaticAddrsForClaim(ctx, claim, podRef, deviceClaimConfigs, staticAddrsMap)

	// Precompute what is already done so retries skip completed work.
	state := driver.newClaimPrepState(podRef, claim)

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
			if _, reused := state.existingByDevice[a.id()]; reused {
				continue
			}
			if err := driver.cleanupAllocation(a); err != nil {
				driver.logger.Warn("failed to rollback device",
					logfields.Device, a.DeviceName,
					logfields.Error, err,
				)
			}
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

	driver.storeAllocations(alloc, podRef.UID, claim.UID)

	// we dont need to return anything here.
	return kubeletplugin.PrepareResult{}
}

func (driver *Driver) deviceClaimConfigs(ctx context.Context, claim *resourceapi.ResourceClaim) (map[string]types.DeviceConfig, error) {
	devicesCfg := map[string]types.DeviceConfig{}
	for _, cfg := range claim.Status.Allocation.Devices.Config {
		if cfg.Opaque == nil || cfg.Opaque.Parameters.Raw == nil {
			continue
		}
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

// allocationID is node-local. The driver publishes one DRA ResourceSlice pool
// per node, so the device name and scheduler-assigned share identify an
// allocation without storing that pool name again.
type allocationID struct {
	Device  string
	ShareID kube_types.UID
}

func allocationIDFromResult(result resourceapi.DeviceRequestAllocationResult) allocationID {
	return allocationID{
		Device:  result.Device,
		ShareID: shareIDFromResult(result),
	}
}

func allocationIDFromStatus(status resourceapi.AllocatedDeviceStatus) allocationID {
	var shareID kube_types.UID
	if status.ShareID != nil {
		shareID = kube_types.UID(*status.ShareID)
	}

	return allocationID{
		Device:  status.Device,
		ShareID: shareID,
	}
}

func shareIDFromResult(result resourceapi.DeviceRequestAllocationResult) kube_types.UID {
	if result.ShareID == nil {
		return ""
	}
	return *result.ShareID
}

func (a allocation) id() allocationID {
	return allocationID{
		Device:  a.DeviceName,
		ShareID: a.ShareID,
	}
}

func (a allocation) deviceAllocation() types.DeviceAllocation {
	return types.DeviceAllocation{
		Config:           a.Config,
		ShareID:          a.ShareID,
		ConsumedCapacity: maps.Clone(a.ConsumedCapacity),
	}
}

// getStaticAddrsForClaim returns the static addresses, extracted from the
// annotation.NetworkDriverStaticAddresses pod annotation, for the specified claim.
func (driver *Driver) getStaticAddrsForClaim(ctx context.Context, claim *resourceapi.ResourceClaim,
	podRef resourceapi.ResourceClaimConsumerReference) (types.StaticAddrsMap, error) {
	pod, err := driver.podForClaim(ctx, claim, podRef)
	if err != nil {
		return nil, err
	}

	if pod == nil {
		return nil, nil
	}

	raw, found := annotation.Get(pod, annotation.NetworkDriverStaticAddresses)
	if !found || strings.TrimSpace(raw) == "" {
		return nil, nil
	}

	podLocalClaimName, err := getPodLocalClaimNameForClaim(pod, claim.Name)
	if err != nil {
		return nil, err
	}

	var claimToStaticAddrsMap map[string]types.StaticAddrsMap
	if err := json.Unmarshal([]byte(raw), &claimToStaticAddrsMap); err != nil {
		return nil, fmt.Errorf("failed to unmarshal %s annotation on pod %s/%s: %w",
			annotation.NetworkDriverStaticAddresses, pod.Namespace, pod.Name, err)
	}

	return claimToStaticAddrsMap[podLocalClaimName], nil
}

// getPodLocalClaimNameForClaim returns the name of the pod local claim entry in pod spec the
// specified claim refers to. If the claim is not generated from a template, and the same claim is
// referenced in multiple pod resource claim entries (i.e.: multiple entries set resourceClaimName
// to the same value), the name of the first entry is returned.
func getPodLocalClaimNameForClaim(pod *corev1.Pod, claimName string) (string, error) {
	for i := range pod.Spec.ResourceClaims {
		localName, _, err := resourceclaim.Name(pod, &pod.Spec.ResourceClaims[i])
		switch {
		case errors.Is(err, draresourceclaim.ErrClaimNotFound):
			// A claim generated from a template may not exist yet.
			continue
		case err != nil:
			return "", fmt.Errorf("unable to retrieve pod %s's local claim name for claim %s",
				path.Join(pod.Namespace, pod.Name), claimName)
		case localName == nil:
			continue
		}

		if *localName == claimName {
			return pod.Spec.ResourceClaims[i].Name, nil
		}
	}
	return "", fmt.Errorf("unable to find pod %s's local claim name for claim %s",
		path.Join(pod.Namespace, pod.Name), claimName)
}

// validateStaticAddrsForClaim validates the static addresses, extracted from the
// annotation.NetworkDriverStaticAddresses pod annotation, for the specified claim.
func (driver *Driver) validateStaticAddrsForClaim(claim *resourceapi.ResourceClaim,
	staticAddrsMap types.StaticAddrsMap) error {
	for claimReq, staticAddrs := range staticAddrsMap {
		if !slices.ContainsFunc(claim.Status.Allocation.Devices.Results,
			func(result resourceapi.DeviceRequestAllocationResult) bool {
				return result.Request == claimReq
			}) {
			return fmt.Errorf("unable to find claim request %s", claimReq)
		}

		ipv4Present, err := driver.validateStaticAddrForClaimReq(staticAddrs.IPv4, true, claimReq)
		if err != nil {
			return err
		}

		ipv6Present, err := driver.validateStaticAddrForClaimReq(staticAddrs.IPv6, false, claimReq)
		if err != nil {
			return err
		}

		// Don't allow addresses to be both absent in case at least one family is enabled.
		if (driver.ipv4Enabled || driver.ipv6Enabled) && !ipv4Present && !ipv6Present {
			return fmt.Errorf("no address specified for any of the enabled families for claim request %s", claimReq)
		}
	}
	return nil
}

// validateStaticAddrForClaimReq validates that the provided address belongs to the right family and
// that is valid. Addresses for disabled families are not allowed.
func (driver *Driver) validateStaticAddrForClaimReq(addr *netip.Prefix, shouldBeIPv4 bool,
	claimReq string) (bool, error) {
	addrPresent := addr != nil

	var isFamilyEnabled bool
	var isAddrFamilyValid func(a netip.Addr) bool
	if shouldBeIPv4 {
		isFamilyEnabled = driver.ipv4Enabled
		isAddrFamilyValid = netip.Addr.Is4
	} else {
		isFamilyEnabled = driver.ipv6Enabled
		isAddrFamilyValid = netip.Addr.Is6
	}

	if !isFamilyEnabled {
		if addrPresent {
			return false, fmt.Errorf("prefix %s for claim request %s belongs to disabled family",
				addr, claimReq)
		}
		return false, nil
	}

	if addrPresent {
		if !addr.IsValid() {
			return false, fmt.Errorf("invalid prefix %s for claim request %s", addr, claimReq)
		}

		if !isAddrFamilyValid(addr.Addr()) {
			return false, fmt.Errorf("family mismatch for prefix %s family for claim request %s",
				addr, claimReq)
		}
		return true, nil
	}

	return false, nil
}

// applyStaticAddrsForClaim applies the static addresses, requested by the user in the
// annotation.NetworkDriverStaticAddresses pod annotation, for the claim.
func (driver *Driver) applyStaticAddrsForClaim(ctx context.Context,
	claim *resourceapi.ResourceClaim, podRef resourceapi.ResourceClaimConsumerReference,
	deviceClaimConfigs map[string]types.DeviceConfig, staticAddrsMap types.StaticAddrsMap) {
	// No annotations for this claim or no family enabled, nothing to apply.
	if len(staticAddrsMap) == 0 || !(driver.ipv4Enabled || !driver.ipv6Enabled) {
		return
	}

	for claimReq, staticAddrs := range staticAddrsMap {
		deviceConfig := deviceClaimConfigs[claimReq]
		deviceConfigMutated := false
		if ipv4Addr := staticAddrs.IPv4; driver.ipv4Enabled && ipv4Addr != nil {
			deviceConfig.IPv4Addr = *ipv4Addr
			deviceConfigMutated = true
			driver.logger.DebugContext(ctx, "applied static IP addresses from pod annotation",
				logfields.K8sNamespace, claim.Namespace,
				logfields.Name, claim.Name,
				logfields.K8sPodName, podRef,
				logfields.IPv4, ipv4Addr,
			)
		}
		if ipv6Addr := staticAddrs.IPv6; driver.ipv6Enabled && ipv6Addr != nil {
			deviceConfig.IPv6Addr = *ipv6Addr
			deviceConfigMutated = true
			driver.logger.DebugContext(ctx, "applied static IP addresses from pod annotation",
				logfields.K8sNamespace, claim.Namespace,
				logfields.Name, claim.Name,
				logfields.K8sPodName, podRef,
				logfields.IPv6, ipv6Addr,
			)
		}
		if deviceConfigMutated {
			deviceClaimConfigs[claimReq] = deviceConfig
		}
	}
}

// claimPrepState holds the precomputed lookups used to make prepareResourceClaim
// idempotent across retries.
type claimPrepState struct {
	// devices already set up for this exact (pod, claim), keyed by allocation identity.
	existingByDevice map[allocationID]allocation
	// devices that already have a status entry in the claim for this driver.
	existingStatusDevice map[allocationID]struct{}
}

// newClaimPrepState builds the idempotency lookups for a (pod, claim) pair:
// which devices were already set up in memory, and which already have a
// Kubernetes status entry. Both let a retry skip work that already completed.
func (driver *Driver) newClaimPrepState(pod resourceapi.ResourceClaimConsumerReference, claim *resourceapi.ResourceClaim) claimPrepState {
	existingByDevice := make(map[allocationID]allocation)
	txn := driver.db.ReadTxn()
	for row := range AllocationsByClaimUID(driver.allocationTable, txn, claim.UID) {
		if row.PodUID != pod.UID || row.PreparedDevice == nil {
			continue
		}
		a := allocationFromRow(row)
		existingByDevice[a.id()] = a
	}

	existingStatusDevice := make(map[allocationID]struct{})
	for _, ds := range claim.Status.Devices {
		if ds.Driver == driver.config.DriverName {
			existingStatusDevice[allocationIDFromStatus(ds)] = struct{}{}
		}
	}

	return claimPrepState{
		existingByDevice:     existingByDevice,
		existingStatusDevice: existingStatusDevice,
	}
}

// validateConfigs checks that every device config in the claim is valid (podIfName, sysctl
// settings) and that every static address config is valid before any destructive work begins.
func (driver *Driver) validateConfigs(claim *resourceapi.ResourceClaim,
	deviceClaimConfigs map[string]types.DeviceConfig, staticAddrsMap map[string]types.StaticAddrs) error {
	for request, cfg := range deviceClaimConfigs {
		if err := types.ValidateInterfaceName(cfg.PodIfName); err != nil {
			return fmt.Errorf("invalid podIfName in request %s for claim %s: %w",
				request, path.Join(claim.Namespace, claim.Name), err)
		}
		if err := validateInterfaceSysctl(cfg); err != nil {
			return fmt.Errorf("invalid sysctl config in request %s for claim %s: %w",
				request, path.Join(claim.Namespace, claim.Name), err)
		}
	}
	if err := driver.validateStaticAddrsForClaim(claim, staticAddrsMap); err != nil {
		return fmt.Errorf("invalid static addresses for claim %s: %w",
			path.Join(claim.Namespace, claim.Name), err)
	}
	return nil
}

// cleanupAllocation undoes a device allocation: it frees the device and
// releases any pool-allocated addresses. The call is a safe no-op when
// there is nothing to undo.
func (driver *Driver) cleanupAllocation(a allocation) error {
	var errs []error
	if err := driver.releaseAddrs(a.Config); err != nil {
		errs = append(errs, fmt.Errorf("failed to release addresses: %w", err))
	}
	if a.Device != nil {
		if err := a.Device.Free(a.deviceAllocation()); err != nil {
			errs = append(errs, fmt.Errorf("failed to free device: %w", err))
		} else {
			a.Device = nil
		}
	}
	return errors.Join(errs...)
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
) (allocation, *resourceapi.AllocatedDeviceStatus, error) {

	// Idempotency: reuse a device already set up for this (pod, claim) instead
	// of setting it up again. This returns before any setup, so the rollback
	// below is never armed for a reused device.
	if reused, reuseStatus, reuseErr := driver.reuseAllocatedDevice(claim, result, state); reuseErr != nil {
		return allocation{}, nil, reuseErr
	} else if reused != nil {
		return *reused, reuseStatus, nil
	}

	// New device: set it up.
	return driver.getNewAllocation(ctx, claim, result, cfg)
}

// getNewAllocation sets up the kernel device for a newly allocated claim
// device result.
func (driver *Driver) getNewAllocation(
	ctx context.Context,
	claim *resourceapi.ResourceClaim,
	result resourceapi.DeviceRequestAllocationResult,
	cfg types.DeviceConfig,
) (allocation, *resourceapi.AllocatedDeviceStatus, error) {
	draDevice, _, found := driver.deviceTable.Get(driver.db.ReadTxn(),
		deviceByName.Query(result.Device))
	if !found || draDevice.Dev == nil {
		return allocation{}, nil, fmt.Errorf("%w with ifname %s", errDeviceNotFound, result.Device)
	}

	claimNamespacedName := path.Join(claim.Namespace, claim.Name)
	alloc := allocation{
		DeviceName:       result.Device,
		Config:           cfg,
		ShareID:          shareIDFromResult(result),
		ConsumedCapacity: maps.Clone(result.ConsumedCapacity),
	}

	// Setup the rollback function to clean up the device if any subsequent step fails.
	var (
		errMsg string
		err    error
	)
	defer func() {
		if err != nil {
			driver.logger.ErrorContext(ctx, errMsg,
				logfields.Device, alloc.DeviceName,
				logfields.PoolName, cfg.IPPool,
				logfields.Error, err,
			)
			if err := driver.cleanupAllocation(alloc); err != nil {
				driver.logger.Warn("failed to rollback device",
					logfields.Device, alloc.DeviceName,
					logfields.Error, err,
				)
			}
		}
	}()

	// Allocate IP addresses
	if err = driver.allocateAddrs(ctx, alloc.DeviceName, &alloc.Config); err != nil {
		errMsg = "failed to allocate IP addresses"
		return allocation{}, nil, fmt.Errorf("%s for device %s in claim %s: %w", errMsg, alloc.DeviceName, claimNamespacedName, err)
	}

	// Setup the device. The prepared device may differ from the advertised
	// device when setup creates allocation-specific state.
	alloc.Manager = draDevice.Manager
	var prepared types.Device
	if prepared, err = draDevice.Dev.Setup(alloc.deviceAllocation()); err != nil {
		errMsg = "failed to set up device"
		return allocation{}, nil, fmt.Errorf("%s for ifname %s in claim %s: %w", errMsg, alloc.DeviceName, claimNamespacedName, err)
	}
	if prepared == nil {
		errMsg = "failed to set up device"
		err = fmt.Errorf("device %s returned no prepared device", result.Device)
		return allocation{}, nil, fmt.Errorf("%s for ifname %s in claim %s: %w", errMsg, alloc.DeviceName, claimNamespacedName, err)
	}
	alloc.Device = prepared
	alloc.LogicalPool = driver.resolvePool(draDevice.Dev, driver.config.Pools)

	// Build the device status
	var built resourceapi.AllocatedDeviceStatus
	built, err = driver.buildDeviceStatus(claim, result, alloc)
	if err != nil {
		errMsg = "failed to build status"
		return allocation{}, nil, fmt.Errorf("%s for device %s in claim %s: %w", errMsg, alloc.Device.IfName(), claimNamespacedName, err)
	}

	return alloc, &built, nil
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
	id := allocationIDFromResult(result)
	existing, alreadyDone := state.existingByDevice[id]
	if !alreadyDone {
		return nil, nil, nil
	}

	if _, statusPresent := state.existingStatusDevice[id]; statusPresent {
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
	ips := make([]string, 0, 2)
	if driver.ipv4Enabled && a.Config.IPv4Addr.IsValid() {
		ips = append(ips, a.Config.IPv4Addr.String())
	}
	if driver.ipv6Enabled && a.Config.IPv6Addr.IsValid() {
		ips = append(ips, a.Config.IPv6Addr.String())
	}

	var shareID *string
	if a.ShareID != "" {
		shareID = ptr.To(string(a.ShareID))
	}

	return resourceapi.AllocatedDeviceStatus{
		Driver:     driver.config.DriverName,
		Pool:       result.Pool,
		Device:     result.Device,
		ShareID:    shareID,
		Conditions: []metav1.Condition{conditionReady(claim)},
		Data:       &runtime.RawExtension{Raw: rawDev},
		NetworkData: &resourceapi.NetworkDeviceData{
			InterfaceName: ifName,
			IPs:           ips,
		},
	}, nil
}

// conflictingDeviceForPod returns the name of the first DRA allocation that
// conflicts with a result requested for podUID by a different claim. Different
// non-empty shares of the same device can coexist. The check skips
// skipClaimUID so an idempotent retry is not rejected.
func (driver *Driver) conflictingDeviceForPod(podUID kube_types.UID, skipClaimUID kube_types.UID, results []resourceapi.DeviceRequestAllocationResult) string {
	txn := driver.db.ReadTxn()
	for row := range AllocationsByPodUID(driver.allocationTable, txn, podUID) {
		if row.ClaimUID == skipClaimUID {
			continue
		}

		allocated := allocationID{Device: row.DeviceName, ShareID: row.ShareID}
		for _, result := range results {
			requested := allocationIDFromResult(result)
			if allocated.Device != requested.Device {
				continue
			}
			if allocated.ShareID == "" || requested.ShareID == "" || allocated.ShareID == requested.ShareID {
				return result.Device
			}
		}
	}
	return ""
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
		Manager:          a.Manager,
		Dev:              data,
		Config:           a.Config,
		LogicalPool:      a.LogicalPool,
		ConsumedCapacity: maps.Clone(a.ConsumedCapacity),
	})
}

func deserializeDevice(data []byte) (types.SerializedDevice, error) {
	var dev types.SerializedDevice

	if err := json.Unmarshal(data, &dev); err != nil {
		return types.SerializedDevice{}, err
	}

	return dev, nil
}

func (driver *Driver) releaseAddrs(cfg types.DeviceConfig) error {
	if !cfg.HasPool() {
		// static addresses, no need to release from pool
		return nil
	}

	// if we have a Pool, IPs are allocated from it and need to be released back to the pool
	var errs []error
	if cfg.IPv4Addr.IsValid() {
		if err := driver.multiPoolMgr.ReleaseIP(cfg.IPv4Addr.Addr(), ipam.Pool(cfg.IPPool), ipam.IPv4, true); err != nil {
			errs = append(errs, fmt.Errorf("failed to release IP address: %w", err))
		}
	}
	if cfg.IPv6Addr.IsValid() {
		if err := driver.multiPoolMgr.ReleaseIP(cfg.IPv6Addr.Addr(), ipam.Pool(cfg.IPPool), ipam.IPv6, true); err != nil {
			errs = append(errs, fmt.Errorf("failed to release IP address: %w", err))
		}
	}
	return errors.Join(errs...)
}

func (driver *Driver) allocateAddrs(ctx context.Context, deviceName string, cfg *types.DeviceConfig) error {
	const (
		// addrAddRetryInterval is the initial interval for the exponential backoff between
		// subsequent "address add request" retries to the IPAM manager.
		// This is needed when requesting an IP address from a not yet ready pool, in order
		// to let the operator handle the new request and reserve a CIDR for the node.
		addrAddRetryInterval = time.Second

		// addrAddMaxRetries is the maximum number of "address add request" retries before
		// failing the operation. After reaching the maximum number of retries, we return an error
		// and the kubelet will call again us to retry the operation.
		addrAddMaxRetries = 3
	)

	if !cfg.HasPool() {
		// static addresses, no need to allocate from the pool
		return nil
	}

	if cfg.IPv4Addr.IsValid() || cfg.IPv6Addr.IsValid() {
		// when we call this method we should not have any IP addresses already assigned
		return fmt.Errorf("device %s already has an IP address assigned", deviceName)
	}

	if err := resiliency.Retry(ctx, addrAddRetryInterval, addrAddMaxRetries, func(ctx context.Context, retries int) (bool, error) {
		var errs []error
		// it is possible that in one retry we successfully allocate an IPv4
		// address but fail to allocate an IPv6 address, or vice versa.
		// So we need to check if we already have a valid ip address before
		// attempting to allocate a new one.
		if driver.ipv4Enabled && !cfg.IPv4Addr.IsValid() {
			res, err := driver.multiPoolMgr.AllocateNext(deviceName, ipam.Pool(cfg.IPPool), ipam.IPv4, true)
			if err != nil {
				errs = append(errs, err)
			} else {
				// TODO: We need to use the prefix of the CIDR from which the IP was allocated
				// rather than the IP's bit length.
				// e.g., if the IP was allocated from a /24 CIDR (in the CiliumResourceIPPool),
				// we should use 24 as the prefix length.
				cfg.IPv4Addr = netip.PrefixFrom(res.IP, res.IP.BitLen())
			}
		}
		if driver.ipv6Enabled && !cfg.IPv6Addr.IsValid() {
			res, err := driver.multiPoolMgr.AllocateNext(deviceName, ipam.Pool(cfg.IPPool), ipam.IPv6, true)
			if err != nil {
				errs = append(errs, err)
			} else {
				// TODO: We need to use the prefix of the CIDR from which the IP was allocated
				// rather than the IP's bit length.
				cfg.IPv6Addr = netip.PrefixFrom(res.IP, res.IP.BitLen())
			}
		}
		if len(errs) != 0 {
			driver.logger.WarnContext(
				ctx, "failed to get IP addresses for device, will retry",
				logfields.Device, deviceName,
				logfields.PoolName, cfg.IPPool,
				logfields.Error, errs,
			)
			return false, nil
		}
		return true, nil
	}); err != nil {
		// it is possible that some IP addresses were successfully allocated before the failure occurred.
		return errors.Join(err, driver.releaseAddrs(*cfg))
	}
	return nil
}
