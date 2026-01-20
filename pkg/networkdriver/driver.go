// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package networkdriver

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"path"
	"slices"

	"github.com/blang/semver/v4"
	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/containerd/nri/pkg/stub"
	corev1 "k8s.io/api/core/v1"
	resourceapi "k8s.io/api/resource/v1"
	kube_types "k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	"k8s.io/dynamic-resource-allocation/kubeletplugin"
	"k8s.io/dynamic-resource-allocation/resourceslice"
	"k8s.io/utils/ptr"

	"github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	"github.com/cilium/cilium/pkg/k8s/resource"
	"github.com/cilium/cilium/pkg/k8s/version"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/networkdriver/devicemanagers"
	"github.com/cilium/cilium/pkg/networkdriver/types"
	"github.com/cilium/cilium/pkg/node"
	ciliumslices "github.com/cilium/cilium/pkg/slices"
	"github.com/cilium/cilium/pkg/time"
)

var (
	defaultDriverPluginPath = "/var/lib/kubelet/plugins/"
)

func driverPluginPath(driverName string) string {
	return path.Join(defaultDriverPluginPath, driverName)
}

type Driver struct {
	kubeClient     kubernetes.Interface
	draPlugin      *kubeletplugin.Helper
	nriPlugin      stub.Stub
	logger         *slog.Logger
	lock           lock.Mutex
	jg             job.Group
	resourceClaims resource.Resource[*resourceapi.ResourceClaim]
	pods           resource.Resource[*corev1.Pod]

	configCRD resource.Resource[*v2alpha1.CiliumNetworkDriverConfig]
	config    *v2alpha1.CiliumNetworkDriverConfig

	deviceManagers map[types.DeviceManagerType]types.DeviceManager
	// pod.UID: claim.UID: allocation
	allocations map[kube_types.UID]map[kube_types.UID][]allocation
	// manager_type: devices
	devices        map[types.DeviceManagerType][]types.Device
	localNodeStore *node.LocalNodeStore
}

type allocation struct {
	Device  types.Device
	Config  types.DeviceConfig
	Manager types.DeviceManagerType
}

func (driver *Driver) withLock(f func() error) error {
	driver.lock.Lock()
	defer driver.lock.Unlock()

	return f()
}

// filterDevices returns the resulting devices after applying a filter.
func filterDevices(devices []types.Device, filter v2alpha1.CiliumNetworkDriverDeviceFilter) []types.Device {
	var result []types.Device

	for _, d := range devices {
		if d.Match(filter) {
			result = append(result, d)
		}
	}

	return result
}

// getDevicePools queries each device manager for their devices, and group them into pools
// that are advertised as resourceslices to the kube-api.
func (driver *Driver) getDevicePools(ctx context.Context) (map[string]resourceslice.Pool, error) {
	driver.devices = make(map[types.DeviceManagerType][]types.Device)

	for m, mgr := range driver.deviceManagers {
		devices, err := mgr.ListDevices()
		if err != nil {
			return nil, err
		}

		if len(devices) > 0 {
			driver.logger.DebugContext(
				ctx, "retrieved devices from devicemanager",
				logfields.DriverName, m,
				logfields.Devices, len(devices),
			)

			driver.devices[mgr.Type()] = append(driver.devices[mgr.Type()], devices...)
		}
	}

	pools := make(map[string]resourceslice.Pool, len(driver.config.Spec.Pools))

	for _, p := range driver.config.Spec.Pools {
		if p.Filter == nil {
			// no filter specified, this shouldn't happen
			driver.logger.ErrorContext(
				ctx, "pool filter is missing. not handling this pool",
				logfields.PoolName, p.PoolName,
			)

			continue
		}
		var filtered []types.Device
		for devs := range maps.Values(driver.devices) {
			filtered = filterDevices(devs, *p.Filter)
		}

		var devices []resourceapi.Device

		for _, dev := range filtered {
			if dev.IfName() == "" {
				// all devices need a name
				driver.logger.Error("received device without a name", logfields.Attributes, dev.GetAttrs())
				continue
			}

			attrs := dev.GetAttrs()
			attrs["pool"] = resourceapi.DeviceAttribute{StringValue: ptr.To(p.PoolName)}
			devices = append(devices, resourceapi.Device{
				Name:       dev.IfName(),
				Attributes: attrs,
			})
		}

		driver.logger.DebugContext(
			ctx, "devices matched filter for pool",
			logfields.PoolName, p.PoolName,
			logfields.Devices, filtered,
		)

		pools[p.PoolName] = resourceslice.Pool{
			Slices: []resourceslice.Slice{
				{Devices: devices},
			},
		}
	}

	return pools, nil
}

// publish publishes the mock sriov devices to the kubelet plugin api.
// these show up in the cluster as resource.k8s.io/v1/ResourceSlice after published.
func (driver *Driver) publish(ctx context.Context) error {
	return driver.withLock(func() error {
		pools, err := driver.getDevicePools(ctx)
		if err != nil {
			driver.logger.ErrorContext(ctx, "failed to list devices", logfields.Error, err)
			return err
		}

		res := resourceslice.DriverResources{
			Pools: pools,
		}

		driver.logger.DebugContext(ctx, "publishing resourceslices", logfields.Count, len(res.Pools))

		return driver.draPlugin.PublishResources(ctx, res)
	})
}

// watchConfig blocks until the first configuration is found (from the CRD). Update attempts are logged but not passed
// to the channel
func (driver *Driver) watchConfig(ctx context.Context) <-chan *v2alpha1.CiliumNetworkDriverConfig {
	ch := make(chan *v2alpha1.CiliumNetworkDriverConfig)

	go func() {
		defer close(ch)

		var (
			synced, handled bool
			cfgs            = make(map[kube_types.UID]*v2alpha1.CiliumNetworkDriverConfig)
		)

		if driver.configCRD == nil {
			// disabled
			return
		}

		// Upon starting, we expect to receive all the current CRDs in events
		// of kind "upsert", followed by an event of kind "sync".
		// we collect all the configs, and on every update we evaluate
		// the selector to determine if an update is necessary or not.
		for ev := range driver.configCRD.Events(ctx) {
			ev.Done(nil)

			switch ev.Kind {
			case resource.Sync:
				synced = true
			case resource.Delete:
				delete(cfgs, ev.Object.GetUID())
				continue
			case resource.Upsert:
				if ev.Object.Spec.NodeSelector == nil {
					cfgs[ev.Object.GetUID()] = ev.Object.DeepCopy()
				} else {
					thisNode, err := driver.localNodeStore.Get(ctx)
					if err != nil {
						driver.logger.ErrorContext(
							ctx, "failed to retrieve node labels",
							logfields.Error, err,
						)

						continue
					}

					match, err := labelsMatch(ev.Object, thisNode.Labels)
					if err != nil {
						driver.logger.Error("failed to match node labels to selector", logfields.Error, err)
						continue
					}

					if !match {
						driver.logger.Debug("configuration selector does not match this node", logfields.Config, ev.Object.ObjectMeta.Name)
						continue
					}

					driver.logger.Debug("configuration selector matches this node", logfields.Config, ev.Object.ObjectMeta.Name)

					cfgs[ev.Object.GetUID()] = ev.Object.DeepCopy()
				}

			}

			// wait for sync and upsert before reading the config
			if !synced {
				continue
			}

			// discard updates if we already handled a config
			if handled {
				driver.logger.InfoContext(
					ctx, "config received, but we already have one",
				)

				continue
			}

			cfg := selectConfig(slices.Collect(maps.Values(cfgs)))

			if cfg != nil {
				driver.logger.Debug("configuration selected", logfields.Config, cfg.ObjectMeta.Name)
			}

			handled = true
			ch <- cfg
		}
	}()

	return ch
}

func (driver *Driver) deviceFromClaim(devStatus resourceapi.AllocatedDeviceStatus) (allocation, error) {
	devMgrType, devRaw, devCfg, err := deserializeDevice(devStatus.Data.Raw)
	if err != nil {
		return allocation{}, fmt.Errorf("failed to deserialize device from pool %s using device manager type %s", devStatus.Pool, devMgrType)
	}

	devMgr, found := driver.deviceManagers[devMgrType]
	if !found {
		return allocation{}, fmt.Errorf("unknown device manager type %s", devMgrType)
	}

	dev, err := devMgr.RestoreDevice(devRaw)
	if err != nil {
		return allocation{}, fmt.Errorf("failed to restore device from pool %s using device manager type %s", devStatus.Pool, devMgrType)
	}

	return allocation{
		Device:  dev,
		Config:  devCfg,
		Manager: devMgrType,
	}, nil
}

func (driver *Driver) restoreDevicesFromClaim(claim *resourceapi.ResourceClaim) error {
	var errs []error

	for _, devStatus := range claim.Status.Devices {
		if devStatus.Driver != driver.config.Spec.DriverName {
			continue
		}

		alloc, err := driver.deviceFromClaim(devStatus)
		if err != nil {
			errs = append(errs, fmt.Errorf("failed to restore device from claim: %w", err))
			continue
		}

		if len(claim.Status.ReservedFor) != 1 {
			errs = append(errs, fmt.Errorf("unexpected ReservedFor length %d for claim, should be 1", len(claim.Status.ReservedFor)))
			continue
		}
		podUID := claim.Status.ReservedFor[0].UID

		var claimAllocs map[kube_types.UID][]allocation
		claimAllocs, found := driver.allocations[podUID]
		if !found {
			claimAllocs = make(map[kube_types.UID][]allocation)
			driver.allocations[podUID] = claimAllocs
		}
		claimAllocs[claim.UID] = append(claimAllocs[claim.UID], alloc)
	}

	return errors.Join(errs...)
}

func (driver *Driver) restoreDevices(ctx context.Context) error {
	podsStore, err := driver.pods.Store(ctx)
	if err != nil {
		return err
	}

	var localPodClaims []resource.Key
	for _, pod := range podsStore.List() {
		for _, claimRef := range pod.Status.ResourceClaimStatuses {
			if claimRef.ResourceClaimName == nil {
				driver.logger.InfoContext(ctx, "resourceClaimStatuses field is empty for pod, no allocation to restore",
					logfields.K8sNamespace, pod.GetNamespace(),
					logfields.Name, pod.Name,
				)
				continue
			}
			localPodClaims = append(localPodClaims, resource.Key{
				Namespace: pod.GetNamespace(),
				Name:      *claimRef.ResourceClaimName,
			})
		}
	}
	localPodClaims = ciliumslices.Unique(localPodClaims)

	claimsStore, err := driver.resourceClaims.Store(ctx)
	if err != nil {
		return err
	}

	var errs []error
	for _, key := range localPodClaims {
		claim, exists, err := claimsStore.GetByKey(key)
		if err != nil {
			errs = append(errs, fmt.Errorf("failed to get claim %s/%s from store: %w", key.Namespace, key.Name, err))
			continue
		}
		if !exists {
			errs = append(errs, fmt.Errorf("claim %s/%s not found in store", key.Namespace, key.Name))
			continue
		}
		if err := driver.restoreDevicesFromClaim(claim); err != nil {
			errs = append(errs, fmt.Errorf("failed to restore allocated devices from claim %s/%s: %w", claim.Namespace, claim.Name, err))
		}
	}
	return errors.Join(errs...)
}

// Start retrieves and validates the configuration. If configuration is found and valid, it
// initializes all the devicemanagers that are enabled by config, and starts the DRA + NRI registration.
func (driver *Driver) Start(ctx cell.HookContext) error {
	driver.jg.Add(job.OneShot("network-driver-main", func(ctx context.Context, _ cell.Health) error {

		if version.Version().LT(semver.Version{Major: 1, Minor: 34}) {
			driver.logger.InfoContext(
				ctx, "Cilium Network Driver requires Kubernetes v1.34 or later",
				logfields.K8sAPIVersion, version.Version(),
			)

			return nil
		}

		cfg, ok := <-driver.watchConfig(ctx)
		if !ok {
			return nil
		}

		driver.config = cfg

		if driver.config == nil {
			// not found, we wont start the driver
			driver.logger.DebugContext(
				ctx, "Network Driver configuration not found",
			)

			return nil
		}

		driver.logger.DebugContext(
			ctx, "Starting network driver...",
			logfields.K8sAPIVersion, version.Version(),
			logfields.DriverName, driver.config.Spec.DriverName,
		)

		if err := validateConfig(&driver.config.Spec); err != nil {
			driver.logger.ErrorContext(
				ctx, "invalid configuration",
				logfields.Error, err,
			)

			return err
		}

		mgrs, err := devicemanagers.InitManagers(driver.logger, driver.config.Spec.DeviceManagerConfigs)
		if err != nil {
			return err
		}

		driver.deviceManagers = mgrs

		if err := driver.restoreDevices(ctx); err != nil {
			driver.logger.ErrorContext(ctx,
				"failed to restore allocated devices from claims, network driver might be unable to correctly release associated resources",
				logfields.Error, err,
			)
		}

		for pod, claimAllocs := range driver.allocations {
			for claim, allocs := range claimAllocs {
				for _, alloc := range allocs {
					driver.logger.DebugContext(ctx,
						"allocation device restored",
						logfields.PodUID, pod,
						logfields.ClaimUID, claim,
						logfields.Device, alloc.Device.IfName(),
						logfields.Config, alloc.Config,
					)
				}
			}
		}

		if err := driver.startDRA(ctx); err != nil {
			driver.Stop(ctx)
			return err
		}

		if err := driver.startNRI(ctx); err != nil {
			driver.Stop(ctx)
			return err
		}

		trigger := job.NewTrigger()

		driver.jg.Add(
			job.Timer(
				"network-driver-dra-publish-resources",
				driver.publish,
				time.Duration(driver.config.Spec.PublishIntervalSeconds)*time.Second,
				job.WithTrigger(trigger),
			),
		)

		trigger.Trigger()

		return nil
	}))

	return nil
}

// Stop stops the nri and dra hooks.
func (driver *Driver) Stop(ctx cell.HookContext) error {
	driver.logger.DebugContext(ctx, "Stopping network driver...")

	// Stop NRI plugin first
	if driver.nriPlugin != nil {
		driver.nriPlugin.Stop()
	}

	// Stop DRA plugin
	if driver.draPlugin != nil {
		driver.draPlugin.Stop()
	}

	driver.logger.DebugContext(ctx, "Network driver stopped")

	return nil
}
