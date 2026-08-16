// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package networkdriver

import (
	"cmp"
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
	"github.com/cilium/statedb"
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

	configCRD resource.Resource[*v2alpha1.CiliumNetworkDriverNodeConfig]
	config    *v2alpha1.CiliumNetworkDriverNodeConfigSpec

	deviceManagers map[types.DeviceManagerType]types.DeviceManager
	// pod.UID: claim.UID: allocation
	allocations map[kube_types.UID]map[kube_types.UID][]allocation
	// pod.UID: network namespace path. Captured at RunPodSandbox (and rebuilt on
	// plugin (re)connect via Synchronize) so StopPodSandbox can recover the netns on
	// containerd < 2.1, where the stop event carries no namespaces: the sandbox task
	// is already killed, so the NRI PodSandbox spec comes back empty. containerd
	// removes the netns only after the StopPodSandbox hook returns, so the cached
	// path is still valid when we use it. Guarded by lock, like allocations.
	podNetns map[kube_types.UID]string

	db             *statedb.DB
	deviceTable    statedb.RWTable[*DRADevice]
	localNodeStore *node.LocalNodeStore
}

type allocation struct {
	Device  types.Device
	Config  types.DeviceConfig
	Manager types.DeviceManagerType
}

// deviceAllocSnapshot is a minimal snapshot of a single in-memory allocation
// entry used to populate statedb rows during onDevices without holding the lock.
type deviceAllocSnapshot struct {
	podUID   kube_types.UID
	claimUID kube_types.UID
	config   types.DeviceConfig
}

// watchConfig blocks until the first configuration is found (from the CRD). Update attempts are logged but not passed
// to the channel
func (driver *Driver) watchConfig(ctx context.Context) <-chan v2alpha1.CiliumNetworkDriverNodeConfigSpec {
	ch := make(chan v2alpha1.CiliumNetworkDriverNodeConfigSpec)

	go func() {
		defer close(ch)

		var (
			cfg *v2alpha1.CiliumNetworkDriverNodeConfigSpec

			synced   bool
			upserted bool
			handled  bool
		)

		if driver.configCRD == nil {
			// disabled
			driver.logger.DebugContext(
				ctx, "resource listener is nil",
			)

			return
		}

		for ev := range driver.configCRD.Events(ctx) {
			ev.Done(nil)

			switch ev.Kind {
			case resource.Delete:
				cfg = nil
				upserted = false
				continue
			case resource.Sync:
				synced = true
			case resource.Upsert:
				cfg = ev.Object.Spec.DeepCopy()
				upserted = true
			}

			// discard updates if we already handled a config
			if handled {
				driver.logger.InfoContext(
					ctx, "config received, but we already have one",
				)
				continue
			}

			// wait for sync and upsert before reading the config
			if !synced || !upserted {
				continue
			}

			driver.logger.DebugContext(ctx, "network driver configuration found")

			handled = true
			ch <- *cfg
		}
	}()

	return ch
}

// Start retrieves and validates the configuration. If configuration is found and valid, it
// initializes all the devicemanagers that are enabled by config, and starts the DRA + NRI registration.
func (driver *Driver) Start(ctx cell.HookContext) error {
	if version.Version().LT(semver.Version{Major: 1, Minor: 34}) {
		driver.logger.InfoContext(
			ctx, "Cilium Network Driver requires Kubernetes v1.34 or later. not starting",
			logfields.K8sAPIVersion, version.Version(),
		)

		return nil
	}

	driver.jg.Add(job.OneShot("network-driver-main", func(ctx context.Context, _ cell.Health) error {
		cfg, ok := <-driver.watchConfig(ctx)
		if !ok {
			return nil
		}

		driver.config = &cfg

		driver.logger.DebugContext(
			ctx, "Starting network driver...",
			logfields.K8sAPIVersion, version.Version(),
			logfields.DriverName, driver.config.DriverName,
		)

		driver.logger.DebugContext(ctx,
			"starting driver with config",
			logfields.Config, driver.config)

		if err := validateConfig(driver.config); err != nil {
			driver.logger.ErrorContext(
				ctx, "invalid configuration",
				logfields.Error, err,
			)

			return err
		}

		mgrs, err := devicemanagers.InitManagers(driver.logger, driver.config.DeviceManagerConfigs)
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

		// Start one goroutine per device manager. Each manager calls the
		// provided publish callback whenever its device set changes; the
		// callback writes the new set into the statedb table.
		for mgrType, mgr := range driver.deviceManagers {
			driver.jg.Add(job.OneShot(
				fmt.Sprintf("network-driver-device-manager-%s", mgrType),
				func(ctx context.Context, _ cell.Health) error {
					return mgr.Run(ctx, func(devices []types.Device) {
						driver.onDevices(mgrType, devices)
					})
				},
			))
		}

		// Publish loop: watch the device table and re-publish ResourceSlices
		// whenever it changes.
		//
		// The publish loop goroutine and the device manager goroutines below are
		// started concurrently by the job group, so there is no strict ordering
		// between the first onDevices call and the first publish. Two cases:
		//
		//   A. Publish loop wins the race: the table is empty on the first
		//      publish, so an empty ResourceSlice is sent to kubelet. When the
		//      device manager goroutine calls onDevices shortly after, it writes
		//      devices into the table, closing the watch channel and triggering
		//      a second publish with the populated set.
		//
		//   B. Device manager wins the race: onDevices writes devices into the
		//      table before the publish loop has started. The publish loop
		//      obtains a watch on a non-empty table and publishes a populated
		//      ResourceSlice on its very first iteration.
		//
		// Either way, kubelet receives a consistent ResourceSlice — the empty
		// first publish in case A is harmless and immediately superseded.
		// Subsequent publish cycles are triggered by onDevices table writes
		// (device-set changes). Allocation writes (commitAllocation /
		// unprepareResourceClaim) also update the table but do NOT trigger
		// re-publish — allocation state is internal bookkeeping and is not
		// reflected in ResourceSlices.
		driver.jg.Add(job.OneShot(
			"network-driver-dra-publish-resources",
			func(ctx context.Context, _ cell.Health) error {
				for {
					txn := driver.db.ReadTxn()
					_, watch := driver.deviceTable.AllWatch(txn)
					if err := driver.publish(ctx); err != nil {
						driver.logger.ErrorContext(ctx, "failed to publish resources", logfields.Error, err)
					}
					select {
					case <-ctx.Done():
						return nil
					case <-watch:
					}
				}
			},
		))

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

// publish builds the ResourceSlice pool map from the current table snapshot
// and pushes it to the kubelet plugin API.
func (driver *Driver) publish(ctx context.Context) error {
	return driver.withLock(func() error {
		pools := driver.buildPoolsFromTable()

		driver.logger.DebugContext(ctx, "publishing resourceslices", logfields.Count, len(pools))

		return driver.draPlugin.PublishResources(ctx, resourceslice.DriverResources{Pools: pools})
	})
}

func (driver *Driver) withLock(f func() error) error {
	driver.lock.Lock()
	defer driver.lock.Unlock()

	return f()
}

// onDevices is called by a device manager whenever its device set changes.
// It writes the full updated set into the statedb table, replacing previous
// rows for that manager, and leaves rows from other managers untouched.
// Allocation state (PodUID, ClaimUID, Config) is preserved for rows that were
// already in the table; for freshly-inserted rows it is populated from
// driver.allocations so that a post-restart call to onDevices immediately
// reflects the restored allocations.
func (driver *Driver) onDevices(mgrType types.DeviceManagerType, devices []types.Device) {
	// Snapshot current allocations under the lock so we can reference them
	// without holding the lock during the (potentially slow) statedb write.
	driver.lock.Lock()
	allocByDevice := make(map[string]deviceAllocSnapshot, len(devices))
	for podUID, claimMap := range driver.allocations {
		for claimUID, allocs := range claimMap {
			for _, a := range allocs {
				if a.Device != nil {
					allocByDevice[a.Device.IfName()] = deviceAllocSnapshot{podUID, claimUID, a.Config}
				}
			}
		}
	}
	driver.lock.Unlock()

	wtxn := driver.db.WriteTxn(driver.deviceTable)
	defer wtxn.Commit()

	// Resolve pool assignment for each device.
	sortedPools := slices.Clone(driver.config.Pools)
	slices.SortFunc(sortedPools, func(a, b v2alpha1.CiliumNetworkDriverDevicePoolConfig) int {
		return cmp.Compare(a.PoolName, b.PoolName)
	})

	seen := make(map[string]struct{}, len(devices))

	for _, dev := range devices {
		ifname := dev.IfName()
		if ifname == "" {
			driver.logger.Error("device manager reported device without a name",
				logfields.Attributes, dev.GetAttrs())
			continue
		}
		seen[ifname] = struct{}{}

		pool := driver.resolvePool(dev, sortedPools)
		if pool == "" {
			// Device matches no pool — skip advertising it.
			continue
		}

		attrs := attrsToPartMap(dev.GetAttrs())

		row := &DRADevice{
			Name:    ifname,
			Manager: mgrType,
			Dev:     dev,
			Pool:    pool,
			Attrs:   attrs,
		}

		// Populate allocation state for newly-inserted rows on a post-restart
		// onDevices call. The merge function below only runs when an existing row
		// is found; on a plain insert Modify stores row directly without calling
		// the merge function, so the stamp must live on row itself.
		if alloc, ok := allocByDevice[ifname]; ok {
			row.PodUID = alloc.podUID
			row.ClaimUID = alloc.claimUID
			row.Config = alloc.config
		}

		_, _, err := driver.deviceTable.Modify(wtxn, row, func(old, _ *DRADevice) *DRADevice {
			// Row already exists: preserve allocation state and update device fields.
			updated := old.Clone()
			updated.Dev = dev
			updated.Attrs = attrs
			return updated
		})

		if err != nil {
			driver.logger.Error(
				"failed to modify statedb object",
				logfields.Error, err,
			)
		}
	}

	// Remove rows for this manager's devices that are no longer reported.
	for d := range driver.deviceTable.All(wtxn) {
		if d.Manager != mgrType {
			continue
		}
		if _, ok := seen[d.Name]; !ok {
			driver.deviceTable.Delete(wtxn, d)
		}
	}
}

// addToAllocations stores alloc under driver.allocations[podUID][claimUID],
// creating the inner map on first use.
func (driver *Driver) addToAllocations(podUID, claimUID kube_types.UID, alloc allocation) {
	if driver.allocations[podUID] == nil {
		driver.allocations[podUID] = make(map[kube_types.UID][]allocation)
	}
	driver.allocations[podUID][claimUID] = append(driver.allocations[podUID][claimUID], alloc)
}

// removeAllocation removes all allocations for claimUID from driver.allocations,
// returning the slice of allocations that were held (nil if none found) and
// whether an entry was present. The pod entry is pruned when it becomes empty.
func (driver *Driver) removeAllocation(claimUID kube_types.UID) ([]allocation, bool) {
	for podUID, claimMap := range driver.allocations {
		allocs, ok := claimMap[claimUID]
		if !ok {
			continue
		}
		delete(claimMap, claimUID)
		if len(claimMap) == 0 {
			delete(driver.allocations, podUID)
		}
		return allocs, true
	}
	return nil, false
}

// setAllocationInTable updates the statedb row for each device in allocs with
// the given podUID and claimUID, or clears those fields when clearing is true.
// It scans all rows to find devices by name — device counts are small so a
// linear scan is fine. Called under driver.lock (commitAllocation and
// unprepareResourceClaim both hold it).
func (driver *Driver) setAllocationInTable(allocs []allocation, podUID, claimUID kube_types.UID, clearing bool) {
	wtxn := driver.db.WriteTxn(driver.deviceTable)
	defer wtxn.Commit()

	// Build a name→allocation index so each row lookup is O(1).
	byName := make(map[string]allocation, len(allocs))
	for _, a := range allocs {
		if a.Device != nil {
			byName[a.Device.IfName()] = a
		}
	}

	for d := range driver.deviceTable.All(wtxn) {
		a, ok := byName[d.Name]
		if !ok {
			continue
		}

		row := d.Clone()
		if clearing {
			row.PodUID = ""
			row.ClaimUID = ""
			row.Config = types.DeviceConfig{}
		} else {
			row.PodUID = podUID
			row.ClaimUID = claimUID
			row.Config = a.Config
		}

		driver.deviceTable.Insert(wtxn, row)
	}
}

// resolvePool returns the single pool name the device should be assigned to.
// If the device matches multiple pools, the first alphabetically is chosen and
// a conflict is logged. Returns "" if no pool matches.
func (driver *Driver) resolvePool(dev types.Device, sortedPools []v2alpha1.CiliumNetworkDriverDevicePoolConfig) string {
	matches := make([]string, 0, len(sortedPools))
	for _, p := range sortedPools {
		if p.Filter == nil {
			continue
		}

		if dev.Match(*p.Filter) {
			matches = append(matches, p.PoolName)
		}
	}

	if len(matches) == 0 {
		return ""
	}

	if len(matches) > 1 {
		driver.logger.Error("device matches multiple pools — assigning to first alphabetically",
			logfields.Device, dev.IfName(),
			logfields.PoolName, matches,
		)
	}

	return matches[0]
}

// buildPoolsFromTable constructs the ResourceSlice pool map from the current
// table snapshot. It pre-populates every configured pool (with a valid filter)
// so pools with no devices are still published as empty slices.
func (driver *Driver) buildPoolsFromTable() map[string]resourceslice.Pool {
	txn := driver.db.ReadTxn()

	pools := make(map[string]resourceslice.Pool, len(driver.config.Pools))
	for _, p := range driver.config.Pools {
		if p.Filter != nil {
			pools[p.PoolName] = resourceslice.Pool{Slices: []resourceslice.Slice{{}}}
		}
	}

	for d := range driver.deviceTable.All(txn) {
		entry, ok := pools[d.Pool]
		if !ok {
			continue
		}

		attrs := maps.Collect(d.Attrs.All())
		attrs[types.PoolNameLabel] = resourceapi.DeviceAttribute{StringValue: ptr.To(d.Pool)}

		entry.Slices[0].Devices = append(entry.Slices[0].Devices, resourceapi.Device{
			Name:       d.Name,
			Attributes: attrs,
		})
		pools[d.Pool] = entry
	}

	return pools
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

	// Detect the crash-before-UpdateStatus case: the claim is allocated and
	// reserved (the scheduler+kubelet did their part) but Status.Devices is
	// empty because the driver crashed between Device.Setup() and UpdateStatus.
	// We have no serialized device state to restore from, so the kernel device
	// is left configured but completely invisible to the driver. Log a warning
	// so the operator can identify and manually clean up the orphaned device.
	if claim.Status.Allocation != nil && len(claim.Status.ReservedFor) > 0 && len(claim.Status.Devices) == 0 {
		driver.logger.Warn("claim is allocated and reserved but has no device status — "+
			"driver may have crashed before UpdateStatus; the kernel device may be orphaned",
			logfields.Name, claim.Name,
			logfields.K8sNamespace, claim.Namespace,
			logfields.UID, string(claim.UID),
		)
	}

	for _, devStatus := range claim.Status.Devices {
		if devStatus.Driver != driver.config.DriverName {
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
		driver.addToAllocations(podUID, claim.UID, alloc)
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
