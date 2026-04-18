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
	"slices"

	"go4.org/netipx"
	resourceapi "k8s.io/api/resource/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	kube_types "k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/dynamic-resource-allocation/kubeletplugin"

	"github.com/cilium/cilium/pkg/ipam"
	"github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/labels"
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

type netDevConfig struct {
	ipPool string
	ipv4   netip.Prefix
	ipv6   netip.Prefix
	routes []route
}

func (driver *Driver) netConfigForDevice(ctx context.Context, device string, cfg types.DeviceConfig) (netDevConfig, error) {
	var devCfg netDevConfig

	devCfg.ipv4 = cfg.IPv4Addr
	devCfg.ipv6 = cfg.IPv6Addr

	if cfg.NetworkConfig == "" {
		return devCfg, nil
	}

	netCfg, _, found := driver.resourceNetworkConfigs.Get(driver.db.ReadTxn(), ResourceNetworkConfigByName(cfg.NetworkConfig))
	if !found {
		return devCfg, fmt.Errorf("no network config %s found for device %s", cfg.NetworkConfig, device)
	}

	node, err := driver.localNodeStore.Get(ctx)
	if err != nil {
		return devCfg, fmt.Errorf("failed to get local node: %w", err)
	}

	targetIdx := slices.IndexFunc(netCfg.Specs, func(cfgSpec spec) bool {
		return cfgSpec.NodeSelector.Matches(labels.Set(node.Labels))
	})
	if targetIdx < 0 {
		return devCfg, fmt.Errorf("no spec matching current node found in network config %s for device %s", cfg.NetworkConfig, device)
	}
	targetCfg := &netCfg.Specs[targetIdx]

	devCfg.routes = make([]route, 0, len(targetCfg.IPv4Routes)+len(targetCfg.IPv6Routes))
	devCfg.routes = append(targetCfg.IPv4Routes, targetCfg.IPv6Routes...)

	// just like the static IP addresses, if a pool is configured in the claim
	// itself it takes precedence over the one in the CiliumResourceNetworkConfig
	pool := cfg.IPPool
	if pool == "" {
		pool = targetCfg.IPPool
	}

	v4FromPool := !cfg.IPv4Addr.IsValid() && pool != ""
	v6FromPool := !cfg.IPv6Addr.IsValid() && pool != ""

	if v4FromPool || v6FromPool {
		if v4FromPool && !driver.ipv4Enabled {
			return devCfg, fmt.Errorf("unable to allocate an IPv4 address from resource pool %s for device %s: IPv4 support is not enabled", pool, device)
		}
		if v6FromPool && !driver.ipv6Enabled {
			return devCfg, fmt.Errorf("unable to allocate an IPv6 address from resource pool %s for device %s: IPv6 support is not enabled", pool, device)
		}

		devCfg.ipPool = pool

		v4PoolAddr, v6PoolAddr, err := driver.addrsForDevice(ctx, device, ipam.Pool(pool), v4FromPool, v6FromPool)

		// persist allocated addresses into device config even in case of error:
		// this way the addresses will be released during rollback, if needed
		if v4FromPool {
			devCfg.ipv4 = netip.PrefixFrom(v4PoolAddr, targetCfg.IPv4NetMask)
		}
		if v6FromPool {
			devCfg.ipv6 = netip.PrefixFrom(v6PoolAddr, targetCfg.IPv6NetMask)
		}

		if err != nil {
			return devCfg, err
		}
	}

	return devCfg, nil
}

func (driver *Driver) addrsForDevice(ctx context.Context, device string, pool ipam.Pool, v4Needed, v6Needed bool) (netip.Addr, netip.Addr, error) {
	var v4Addr, v6Addr netip.Addr

	if err := resiliency.Retry(ctx, AddrAddRetryInterval, AddrAddMaxRetries, func(ctx context.Context, retries int) (bool, error) {
		var errs []error
		if v4Needed && !v4Addr.IsValid() {
			res, err := driver.multiPoolMgr.AllocateNext(device, pool, ipam.IPv4, true)
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
			res, err := driver.multiPoolMgr.AllocateNext(device, pool, ipam.IPv6, true)
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
				logfields.PoolName, pool,
				logfields.Error, errors.Join(errs...),
			)
			return false, nil
		}
		return true, nil
	}); err != nil {
		return v4Addr, v6Addr, fmt.Errorf("failed to get IP addresses for device %s from pool %s: %w", device, pool, err)
	}
	return v4Addr, v6Addr, nil
}

func (driver *Driver) deviceFromRequestResult(result resourceapi.DeviceRequestAllocationResult) (types.DeviceManagerType, types.Device, error) {
	for mgr, devices := range driver.devices {
		if i := slices.IndexFunc(devices, func(dev types.Device) bool {
			return dev.IfName() == result.Device
		}); i >= 0 {
			return mgr, devices[i], nil
		}
	}
	return types.DeviceManagerTypeUnknown, nil, errDeviceNotFound
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

	var (
		devCfg netDevConfig
		err    error
	)

	// release addresses in case of error
	defer func() {
		if err != nil {
			if releaseErr := driver.releaseAddrs(alloc.Config); releaseErr != nil {
				driver.logger.Warn("failed to release addresses for failed device during rollback",
					logfields.Device, alloc.Device.IfName(),
					logfields.Error, releaseErr,
				)
			}
		}
	}()

	devCfg, err = driver.netConfigForDevice(ctx, result.Device, cfg)

	// persist addresses before checking for errors, so that
	// they can be released properly even in case of failures
	alloc.Config.IPv4Addr = devCfg.ipv4
	alloc.Config.IPv6Addr = devCfg.ipv6
	alloc.Config.IPPool = devCfg.ipPool
	alloc.Config.Routes = make([]types.Route, 0, len(devCfg.routes))
	for _, r := range devCfg.routes {
		alloc.Config.Routes = append(alloc.Config.Routes, types.Route{
			Destination: r.Destination,
			Gateway:     r.Gateway,
		})
	}

	if err != nil {
		driver.logger.ErrorContext(
			ctx, "failed to get valid network configuration for device",
			logfields.Device, result.Device,
			logfields.PoolName, cfg.IPPool,
			logfields.Error, err,
		)

		return alloc, fmt.Errorf("failed to get valid network configuration for device %s in claim %s: %w", result.Device, claim, err)
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
		cfg, found := deviceClaimConfigs[result.Request]
		if !found {
			err = fmt.Errorf("%w with ifname %s for %s", errDeviceClaimConfigNotFound, result.Device, path.Join(claim.Namespace, claim.Name))
			return kubeletplugin.PrepareResult{
				Err: err,
			}
		}

		var thisAlloc allocation

		var (
			mgr types.DeviceManagerType
			dev types.Device
		)
		mgr, dev, err = driver.deviceFromRequestResult(result)
		if err != nil {
			err = fmt.Errorf("%w with ifname %s for %s", errDeviceNotFound, result.Device, path.Join(claim.Namespace, claim.Name))
			return kubeletplugin.PrepareResult{
				Err: err,
			}
		}
		thisAlloc.Manager = mgr
		thisAlloc.Device = dev

		thisAlloc, err = driver.prepareDeviceAllocation(ctx, path.Join(claim.Namespace, claim.Name), result, cfg)
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
		alloc = append(alloc, thisAlloc)

		rawDev, err := serializeDevice(thisAlloc)
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
			Data:       &runtime.RawExtension{Raw: rawDev},
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
