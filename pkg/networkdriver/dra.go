// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package networkdriver

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"

	"go4.org/netipx"
	resourceapi "k8s.io/api/resource/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	kube_types "k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/dynamic-resource-allocation/kubeletplugin"

	"github.com/cilium/cilium/pkg/ipam"
	"github.com/cilium/cilium/pkg/k8s/resource"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/networkdriver/types"
	node_types "github.com/cilium/cilium/pkg/node/types"
	"github.com/cilium/cilium/pkg/resiliency"
	"github.com/cilium/cilium/pkg/time"
)

// HandleError logs out error messages from kubelet.
func (d *Driver) HandleError(ctx context.Context, err error, msg string) {
	d.logger.ErrorContext(
		ctx, "HandleError called:",
		logfields.Error, err,
		logfields.Message, msg,
	)
}

// releaseAddrs returns IP addresses to the pool manager when pool-based
// allocation was used.  Static addresses are a no-op.
func (driver *Driver) releaseAddrs(cfg types.DeviceConfig) error {
	if cfg.IPPool == "" {
		return nil
	}
	var errs []error
	if driver.ipv4Enabled {
		if err := driver.multiPoolMgr.ReleaseIP(cfg.IPv4Addr.Addr().AsSlice(), ipam.Pool(cfg.IPPool), ipam.IPv4, true); err != nil {
			errs = append(errs, fmt.Errorf("failed to release IPv4 address: %w", err))
		}
	}
	if driver.ipv6Enabled {
		if err := driver.multiPoolMgr.ReleaseIP(cfg.IPv6Addr.Addr().AsSlice(), ipam.Pool(cfg.IPPool), ipam.IPv6, true); err != nil {
			errs = append(errs, fmt.Errorf("failed to release IPv6 address: %w", err))
		}
	}
	return errors.Join(errs...)
}

// unprepareResourceClaim removes the allocation for the given claim and frees
// all associated devices and IP addresses.
func (d *Driver) unprepareResourceClaim(ctx context.Context, claim kubeletplugin.NamespacedObject) error {
	// Find which pod owns this claim.
	var podUID kube_types.UID
	for uid, claimAllocs := range d.allocations {
		if _, ok := claimAllocs[claim.UID]; ok {
			podUID = uid
			break
		}
	}

	if podUID == "" {
		d.logger.DebugContext(ctx, "no allocation found for claim",
			logfields.UID, claim.UID,
			logfields.K8sNamespace, claim.Namespace,
			logfields.Name, claim.Name,
		)
		return nil
	}

	// If this is the last claim for the pod and the interfaces are still in the
	// pod netns (RunPodSandbox ran but StopPodSandbox has not yet), move them
	// back to the root netns before freeing the devices.
	if len(d.allocations[podUID]) == 1 {
		if nsPath := d.claimPodNetns(ctx, claim); nsPath != "" {
			if err := d.moveInterfacesToRootNs(ctx, nsPath, d.allocations[podUID]); err != nil {
				d.logger.WarnContext(ctx, "failed to move interfaces back to root netns during unprepare "+
					"(pod netns may already be gone)",
					logfields.UID, claim.UID,
					logfields.Error, err,
				)
			}
		}
	}

	var errs []error
	for _, dev := range d.allocations[podUID][claim.UID] {
		if err := d.releaseAddrs(dev.Config); err != nil {
			errs = append(errs, err)
		}
		if err := dev.Device.Free(dev.Config); err != nil {
			errs = append(errs, err)
		}
	}

	delete(d.allocations[podUID], claim.UID)
	if len(d.allocations[podUID]) == 0 {
		delete(d.allocations, podUID)
	}

	return errors.Join(errs...)
}

// UnprepareResourceClaims gets called whenever we have a request to deallocate a resource claim. ex: pod goes away.
func (driver *Driver) UnprepareResourceClaims(ctx context.Context, claims []kubeletplugin.NamespacedObject) (result map[kube_types.UID]error, err error) {
	driver.logger.DebugContext(ctx, fmt.Sprintf("UnprepareResourceClaims called with %d claims", len(claims)))

	result = make(map[kube_types.UID]error, len(claims))

	err = driver.withLock(func() error {
		for _, c := range claims {
			result[c.UID] = driver.unprepareResourceClaim(ctx, c)
			driver.logger.DebugContext(ctx, "freeing resources for claim",
				logfields.Name, c.Name,
				logfields.K8sNamespace, c.Namespace,
				logfields.UID, string(c.UID),
				logfields.Error, result[c.UID],
			)
		}
		return nil
	})

	return result, err
}

// PrepareResourceClaims gets called when we have a request to allocate a resource claim. we also need to have a way to remember
// the allocations elsewhere so allocation state persist across restarts in the plugin.
// the returned error from this function to the caller is treated as "plugin unhealthy" by kubernetes.
// errors for specific claims should not be returned, and instead reported back inside their corresponding PrepareResult.
func (driver *Driver) PrepareResourceClaims(ctx context.Context, claims []*resourceapi.ResourceClaim) (result map[kube_types.UID]kubeletplugin.PrepareResult, err error) {
	driver.logger.DebugContext(ctx, fmt.Sprintf("PrepareResourceClaims called with %d claims", len(claims)))

	result = make(map[kube_types.UID]kubeletplugin.PrepareResult)

	if err = driver.withLock(func() error {
		// Pass 1: validate all claims before touching any devices.
		// If any claim fails validation the whole batch is rejected with no side effects.
		// here we check that:
		// - if configuration exists, it is valid
		// - whether there are any configuration conflicts
		validated, errs := driver.validateBatch(ctx, claims)
		if errs != nil {
			for uid, err := range errs {
				result[uid] = kubeletplugin.PrepareResult{Err: err}
			}

			return nil
		}

		// Pass 2: execute all validated claims.
		// On any failure, roll back every claim that was already executed.
		var executed []kube_types.UID

		for _, v := range validated {
			res := driver.executeClaim(ctx, v)
			result[v.claim.UID] = res

			if res.Err != nil {
				for _, uid := range executed {
					if err := driver.unprepareResourceClaim(ctx, kubeletplugin.NamespacedObject{
						NamespacedName: kube_types.NamespacedName{Namespace: v.claim.Namespace},
						UID:            uid,
					}); err != nil {
						driver.logger.ErrorContext(ctx, "failed to roll back claim during batch failure",
							logfields.UID, uid,
							logfields.Error, err,
						)
					}
				}

				break
			}

			executed = append(executed, v.claim.UID)
		}

		return nil
	}); err != nil {
		return nil, err
	}

	return result, nil
}

func (driver *Driver) addrsForDevice(ctx context.Context, device string, cfg types.DeviceConfig, v4Needed, v6Needed bool) (netip.Addr, netip.Addr, error) {
	var v4Addr, v6Addr netip.Addr

	if cfg.IPPool == "" {
		return netip.Addr{}, netip.Addr{}, fmt.Errorf("no IP pool found in config for device %s", device)
	}

	if err := resiliency.Retry(ctx, AddrAddRetryInterval, AddrAddMaxRetries, func(ctx context.Context, retries int) (bool, error) {
		var errs []error
		if v4Needed && !v4Addr.IsValid() {
			res, err := driver.multiPoolMgr.AllocateNext(device, ipam.Pool(cfg.IPPool), ipam.IPv4, true)
			if err != nil {
				errs = append(errs, err)
			} else {
				addr, ok := netipx.FromStdIP(res.IP)
				if !ok {
					return false, fmt.Errorf("invalid IPv4 address %s", res.IP)
				}
				v4Addr = addr
			}
		}
		if v6Needed && !v6Addr.IsValid() {
			res, err := driver.multiPoolMgr.AllocateNext(device, ipam.Pool(cfg.IPPool), ipam.IPv6, true)
			if err != nil {
				errs = append(errs, err)
			} else {
				addr, ok := netipx.FromStdIP(res.IP)
				if !ok {
					return false, fmt.Errorf("invalid IPv6 address %s", res.IP)
				}
				v6Addr = addr
			}
		}
		if len(errs) > 0 {
			driver.logger.WarnContext(ctx, "failed to get IP addresses for device, will retry",
				logfields.Device, device,
				logfields.PoolName, cfg.IPPool,
				logfields.Error, errors.Join(errs...),
			)
			return false, nil
		}
		return true, nil
	}); err != nil {
		errs := []error{err}
		if v4Addr.IsValid() {
			if err := driver.multiPoolMgr.ReleaseIP(v4Addr.AsSlice(), ipam.Pool(cfg.IPPool), ipam.IPv4, true); err != nil {
				errs = append(errs, fmt.Errorf("failed to release IPv4 address %s: %w", v4Addr, err))
			}
		}
		if v6Addr.IsValid() {
			if err := driver.multiPoolMgr.ReleaseIP(v6Addr.AsSlice(), ipam.Pool(cfg.IPPool), ipam.IPv6, true); err != nil {
				errs = append(errs, fmt.Errorf("failed to release IPv6 address %s: %w", v6Addr, err))
			}
		}
		return netip.Addr{}, netip.Addr{}, fmt.Errorf("failed to get IP addresses for device %s from pool %s: %w",
			device, cfg.IPPool, errors.Join(errs...))
	}
	return v4Addr, v6Addr, nil
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

func deserializeDevice(data []byte) (types.SerializedDevice, error) {
	var dev types.SerializedDevice
	if err := json.Unmarshal(data, &dev); err != nil {
		return types.SerializedDevice{}, err
	}
	return dev, nil
}

func (driver *Driver) startDRA(ctx context.Context) error {
	driver.logger.DebugContext(ctx, "starting driver",
		logfields.DriverName, driver.config.DriverName,
	)

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
			driver.logger.DebugContext(ctx, "DRA registration status",
				logfields.Status, registrationStatus,
			)
			return registrationStatus.PluginRegistered, nil
		})

	if err != nil {
		return fmt.Errorf("DRA plugin registration failed: %w", err)
	}

	driver.logger.DebugContext(ctx, "DRA plugin registration successful",
		logfields.DriverName, driver.config.DriverName,
	)

	return nil
}

// claimPodNetns reads the PodNetns from the claim status stored in the claims store.
// Returns "" if not set, the claim doesn't exist, or an error occurs.
func (d *Driver) claimPodNetns(ctx context.Context, claim kubeletplugin.NamespacedObject) string {
	if d.resourceClaims == nil {
		return ""
	}
	store, err := d.resourceClaims.Store(ctx)
	if err != nil {
		d.logger.WarnContext(ctx, "failed to get claims store for PodNetns lookup", logfields.Error, err)
		return ""
	}

	obj, exists, err := store.GetByKey(resource.Key{Namespace: claim.Namespace, Name: claim.Name})
	if err != nil || !exists {
		return ""
	}

	for _, devStatus := range obj.Status.Devices {
		if devStatus.Driver != d.config.DriverName || devStatus.Data == nil {
			continue
		}

		sd, err := deserializeDevice(devStatus.Data.Raw)
		if err != nil {
			continue
		}

		if sd.PodNetns != "" {
			return sd.PodNetns
		}
	}

	return ""
}

// patchClaimPodNetns updates the PodNetns field in every device status entry
// for this driver in the given claim. Passing an empty podNetns clears the field.
// This is called asynchronously after RunPodSandbox / StopPodSandbox — errors are
// logged but not fatal.
func (d *Driver) patchClaimPodNetns(ctx context.Context, claim *resourceapi.ResourceClaim, podNetns string) error {
	updated := claim.DeepCopy()

	for i, devStatus := range updated.Status.Devices {
		if devStatus.Driver != d.config.DriverName || devStatus.Data == nil {
			continue
		}

		sd, err := deserializeDevice(devStatus.Data.Raw)
		if err != nil {
			return fmt.Errorf("failed to deserialize device status for claim %s/%s: %w",
				claim.Namespace, claim.Name, err)
		}

		sd.PodNetns = podNetns

		raw, err := json.Marshal(sd)
		if err != nil {
			return fmt.Errorf("failed to serialize device status for claim %s/%s: %w",
				claim.Namespace, claim.Name, err)
		}

		updated.Status.Devices[i].Data = &runtime.RawExtension{Raw: raw}
	}

	if _, err := d.kubeClient.ResourceV1().ResourceClaims(claim.Namespace).
		UpdateStatus(ctx, updated, metav1.UpdateOptions{}); err != nil {
		return fmt.Errorf("failed to update claim status for %s/%s: %w", claim.Namespace, claim.Name, err)
	}

	return nil
}
