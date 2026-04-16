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
	"path"

	"go4.org/netipx"
	resourceapi "k8s.io/api/resource/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	kube_types "k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/dynamic-resource-allocation/kubeletplugin"

	"github.com/cilium/cilium/pkg/ipam"
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

func (driver *Driver) releaseAddrs(cfg types.DeviceConfig) error {
	if cfg.IPPool == "" {
		// static addresses, no need to release from pool
		return nil
	}

	var errs []error
	if driver.ipv4Enabled && cfg.IPPool != "" {
		if err := driver.multiPoolMgr.ReleaseIP(cfg.IPv4Addr.Addr().AsSlice(), ipam.Pool(cfg.IPPool), ipam.IPv4, true); err != nil {
			errs = append(errs, fmt.Errorf("failed to release IP address: %w", err))
		}
	}
	if driver.ipv6Enabled && cfg.IPPool != "" {
		if err := driver.multiPoolMgr.ReleaseIP(cfg.IPv6Addr.Addr().AsSlice(), ipam.Pool(cfg.IPPool), ipam.IPv6, true); err != nil {
			errs = append(errs, fmt.Errorf("failed to release IP address: %w", err))
		}
	}
	return errors.Join(errs...)
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
				if err := d.releaseAddrs(dev.Config); err != nil {
					errs = append(errs, err)
				}
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

// UnprepareResourceClaims gets called whenever we have a request to deallocate a resource claim. ex: pod goes away.
func (driver *Driver) UnprepareResourceClaims(ctx context.Context, claims []kubeletplugin.NamespacedObject) (result map[kube_types.UID]error, err error) {
	driver.logger.DebugContext(ctx, fmt.Sprintf("UnprepareResourceClaims called with %d claims", len(claims)))

	result = make(map[kube_types.UID]error, len(claims))

	err = driver.withLock(func() error {
		for _, c := range claims {
			result[c.UID] = driver.unprepareResourceClaim(ctx, c)
			driver.logger.DebugContext(
				ctx, "freeing resources for claim",
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

func (driver *Driver) deviceClaimConfigs(ctx context.Context, claim *resourceapi.ResourceClaim) (map[string]types.DeviceConfig, error) {
	devicesCfg := map[string]types.DeviceConfig{}
	for _, cfg := range claim.Status.Allocation.Devices.Config {
		if cfg.Opaque.Parameters.Raw != nil {
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
			driver.logger.WarnContext(
				ctx, "failed to get IP addresses for device, will retry",
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
		return netip.Addr{}, netip.Addr{}, fmt.Errorf("failed to get IP addresses for device %s from pool %s: %w", device, cfg.IPPool, errors.Join(errs...))
	}
	return v4Addr, v6Addr, nil
}

func (driver *Driver) prepareResourceClaim(ctx context.Context, claim *resourceapi.ResourceClaim) kubeletplugin.PrepareResult {
	if len(claim.Status.ReservedFor) != 1 {
		return kubeletplugin.PrepareResult{
			Err: fmt.Errorf("%w: Status.ReservedFor field has more than one entry", errUnexpectedInput),
		}
	}

	pod := claim.Status.ReservedFor[0]

	if _, ok := driver.allocations[pod.UID]; ok {
		return kubeletplugin.PrepareResult{
			Err: fmt.Errorf("%w: name: %s, resource: %s, uid: %s", errAllocationAlreadyExistsForPod, pod.Name, pod.Resource, pod.UID),
		}
	}

	deviceClaimConfigs, err := driver.deviceClaimConfigs(ctx, claim)
	if err != nil {
		return kubeletplugin.PrepareResult{Err: err}
	}

	// Validate podIfName in all configs before proceeding
	for request, cfg := range deviceClaimConfigs {
		if err := types.ValidateInterfaceName(cfg.PodIfName); err != nil {
			return kubeletplugin.PrepareResult{
				Err: fmt.Errorf("invalid podIfName in request %s for claim %s: %w",
					request, path.Join(claim.Namespace, claim.Name), err),
			}
		}
	}

	var (
		alloc         []allocation
		devicesStatus []resourceapi.AllocatedDeviceStatus
	)

	// rollback releases IPs and calls Device.Free() for every device that was
	// fully set up before an error interrupted the loop.  It is called on every
	// early-return path inside the device loop below.
	defer func() {
		if err != nil {
			for _, a := range alloc {
				if err := a.Device.Free(a.Config); err != nil {
					driver.logger.Warn("failed to free device during rollback",
						logfields.Device, a.Device.IfName(),
						logfields.Error, err,
					)
				}
				if err := driver.releaseAddrs(a.Config); err != nil {
					driver.logger.Warn("failed to release addresses during rollback",
						logfields.Device, a.Device.IfName(),
						logfields.Error, err,
					)
				}
			}
		}
	}()

	for _, result := range claim.Status.Allocation.Devices.Results {
		var thisAlloc allocation

		cfg, ok := deviceClaimConfigs[result.Request]
		if ok {
			thisAlloc.Config = cfg
		}

		var found bool

		for mgr, devices := range driver.devices {
			for _, device := range devices {
				if device.IfName() == result.Device {
					thisAlloc.Manager = mgr
					thisAlloc.Device = device
					found = true
					break
				}
			}
		}

		if !found {
			err = fmt.Errorf("%w with ifname %s for %s", errDeviceNotFound, result.Device, path.Join(claim.Namespace, claim.Name))
			return kubeletplugin.PrepareResult{
				Err: err,
			}
		}

		var (
			v4Addr, v6Addr, zeroAddr netip.Addr
		)

		// if static IP addresses are not specified, request addresses from the referenced pool
		v4Needed := driver.ipv4Enabled && thisAlloc.Config.IPv4Addr.Addr() == zeroAddr
		v6Needed := driver.ipv6Enabled && thisAlloc.Config.IPv6Addr.Addr() == zeroAddr
		if v4Needed || v6Needed {
			v4Addr, v6Addr, err = driver.addrsForDevice(ctx, result.Device, cfg, v4Needed, v6Needed)
			if err != nil {
				driver.logger.ErrorContext(
					ctx, "failed to get IP addresses for device",
					logfields.Device, result.Device,
					logfields.PoolName, cfg.IPPool,
					logfields.Error, err,
				)

				err = fmt.Errorf("failed to get IP addresses for device %s in claim %s: %w", result.Device, path.Join(claim.Namespace, claim.Name), err)
				return kubeletplugin.PrepareResult{
					Err: err,
				}
			}
		}

		if v4Needed {
			thisAlloc.Config.IPv4Addr = netip.PrefixFrom(v4Addr, v4Addr.BitLen())
		}
		if v6Needed {
			thisAlloc.Config.IPv6Addr = netip.PrefixFrom(v6Addr, v6Addr.BitLen())
		}

		if setupErr := thisAlloc.Device.Setup(thisAlloc.Config); setupErr != nil {
			driver.logger.ErrorContext(ctx, "failed to set up device",
				logfields.Device, thisAlloc.Device.IfName(),
				logfields.Config, thisAlloc.Config,
				logfields.Error, setupErr,
			)

			// thisAlloc is not yet appended to alloc, so release its IPs
			// explicitly before rolling back the already-set-up devices.
			if releaseErr := driver.releaseAddrs(thisAlloc.Config); releaseErr != nil {
				driver.logger.Warn("failed to release addresses for failed device during rollback",
					logfields.Device, thisAlloc.Device.IfName(),
					logfields.Error, releaseErr,
				)
			}

			err = fmt.Errorf("%w for ifname %s on %s", setupErr, thisAlloc.Device.IfName(), path.Join(claim.Namespace, claim.Name))
			return kubeletplugin.PrepareResult{
				Err: err,
			}
		}

		alloc = append(alloc, thisAlloc)

		dev, err := serializeDevice(thisAlloc)
		if err != nil {
			driver.logger.ErrorContext(ctx, "failed to serialize device",
				logfields.Device, thisAlloc.Device.IfName(),
				logfields.Config, thisAlloc.Config,
				logfields.Error, err,
			)

			err = fmt.Errorf("failed to serialize device %s for claim %s: %w", thisAlloc.Device.IfName(), path.Join(claim.Namespace, claim.Name), err)
			return kubeletplugin.PrepareResult{
				Err: err,
			}
		}

		var ips []string

		if thisAlloc.Config.IPv4Addr.IsValid() {
			ips = append(ips, thisAlloc.Config.IPv4Addr.String())
		}

		if thisAlloc.Config.IPv6Addr.IsValid() {
			ips = append(ips, thisAlloc.Config.IPv6Addr.String())
		}

		devicesStatus = append(devicesStatus, resourceapi.AllocatedDeviceStatus{
			Driver:     driver.config.DriverName,
			Pool:       result.Pool,
			Device:     result.Device,
			Conditions: []metav1.Condition{conditionReady(claim)},
			Data:       &runtime.RawExtension{Raw: dev},
			NetworkData: &resourceapi.NetworkDeviceData{
				InterfaceName: func() string {
					if thisAlloc.Config.PodIfName != "" {
						return thisAlloc.Config.PodIfName
					}
					return thisAlloc.Device.IfName()
				}(),
				IPs: ips,
			},
		})
	}

	// Persist the allocation to Kubernetes before committing it to memory.
	// If UpdateStatus fails we roll back the devices so the next
	// PrepareResourceClaims call can start fresh rather than hitting the
	// "allocation already exists" guard.
	newClaim := claim.DeepCopy()
	newClaim.Status.Devices = append(newClaim.Status.Devices, devicesStatus...)

	if _, updateErr := driver.kubeClient.ResourceV1().ResourceClaims(claim.Namespace).UpdateStatus(ctx, newClaim, metav1.UpdateOptions{}); updateErr != nil {
		err = fmt.Errorf("failed to update claim %s status: %w", path.Join(claim.Namespace, claim.Name), updateErr)
		return kubeletplugin.PrepareResult{
			Err: err,
		}
	}

	driver.allocations[pod.UID] = make(map[kube_types.UID][]allocation)
	driver.allocations[pod.UID][claim.UID] = alloc

	// we dont need to return anything here.
	return kubeletplugin.PrepareResult{}
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
