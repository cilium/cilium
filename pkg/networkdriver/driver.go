// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package networkdriver

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"log/slog"
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
	// pod.UID: network namespace path. Captured at RunPodSandbox (and rebuilt on
	// plugin (re)connect via Synchronize) so StopPodSandbox can recover the netns on
	// containerd < 2.1, where the stop event carries no namespaces: the sandbox task
	// is already killed, so the NRI PodSandbox spec comes back empty. containerd
	// removes the netns only after the StopPodSandbox hook returns, so the cached
	// path is still valid when we use it. Guarded by lock.
	podNetns map[kube_types.UID]string

	db             *statedb.DB
	deviceTable    statedb.RWTable[*DRADevice]
	localNodeStore *node.LocalNodeStore
}

type allocation struct {
	Device  types.Device
	Config  types.DeviceConfig
	Manager types.DeviceManagerType
	Pool    string
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

		// Register initializers before spawning goroutines so the Initialized
		// barrier is armed before anything can mark it done.
		wtxn := driver.db.WriteTxn(driver.deviceTable)
		markRestoreDone := driver.deviceTable.RegisterInitializer(wtxn, "restore")
		// Register one initializer per device manager; each is marked done on the
		// manager's first onDevices call so the barrier only clears when every
		// manager has published its initial device set.
		markDoneFuncs := make(map[types.DeviceManagerType]func(statedb.WriteTxn), len(mgrs))
		for mgrType := range mgrs {
			markDoneFuncs[mgrType] = driver.deviceTable.RegisterInitializer(wtxn, fmt.Sprintf("device-manager-%s", mgrType))
		}
		wtxn.Commit()

		if err := driver.restoreDevices(ctx, markRestoreDone); err != nil {
			driver.logger.ErrorContext(ctx,
				"failed to restore allocated devices from claims, network driver might be unable to correctly release associated resources",
				logfields.Error, err,
			)
		}

		// Start one goroutine per device manager. Each manager calls the
		// provided publish callback whenever its device set changes; the
		// callback marks that manager's initializer done on its first call
		// so the Initialized barrier clears only after every manager has
		// published its initial device set.
		for mgrType, mgr := range driver.deviceManagers {
			markDevicesDone := markDoneFuncs[mgrType]
			driver.jg.Add(job.OneShot(
				fmt.Sprintf("network-driver-device-manager-%s", mgrType),
				func(ctx context.Context, _ cell.Health) error {
					return mgr.Run(ctx, func(devices []types.Device) {
						driver.onDevices(mgrType, devices, markDevicesDone)
					})
				},
			))
		}

		// Block until all initializers have fired: restored allocations are in
		// the table AND every device manager has published its initial device set.
		// Only then do we register with kubelet — no DRA/NRI callback can arrive
		// before the table is fully populated.
		for {
			txn := driver.db.ReadTxn()
			ok, watch := driver.deviceTable.Initialized(txn)
			if ok {
				break
			}
			select {
			case <-ctx.Done():
				return nil
			case <-watch:
			}
		}

		driver.logger.DebugContext(ctx, "device table initialized")

		if err := driver.startDRA(ctx); err != nil {
			driver.Stop(ctx)
			return err
		}

		if err := driver.startNRI(ctx); err != nil {
			driver.Stop(ctx)
			return err
		}

		// Publish loop: watch the device table and re-publish ResourceSlices
		// whenever it changes.
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
// already in the table (restored by restoreDevices before any DRA callbacks).
//
// markDevicesDone is called on the first invocation, signalling that this
// manager has published its initial device set. The Initialized barrier
// clears only after all managers have called their respective markDevicesDone.
func (driver *Driver) onDevices(mgrType types.DeviceManagerType, devices []types.Device, markDevicesDone func(statedb.WriteTxn)) {
	wtxn := driver.db.WriteTxn(driver.deviceTable)
	defer wtxn.Commit()

	seen := make(map[string]struct{}, len(devices))

	for _, dev := range devices {
		ifname := dev.IfName()
		if ifname == "" {
			driver.logger.Error("device manager reported device without a name",
				logfields.Attributes, dev.GetAttrs())
			continue
		}
		seen[ifname] = struct{}{}

		row := &DRADevice{
			Name:    ifname,
			Manager: mgrType,
			Dev:     dev,
		}

		_, _, err := driver.deviceTable.Modify(wtxn, row, func(old, _ *DRADevice) *DRADevice {
			// Row already exists (written by restoreDevices or a prior onDevices call):
			// update the live device handle, but preserve allocation state.
			updated := old.Clone()
			updated.Dev = dev
			if old.Dev != nil {
				updated.Dev.Merge(old.Dev)
			}
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

	// Mark this manager's initializer done on the first call.
	markDevicesDone(wtxn)
}

// allocationsForPod returns all allocations currently held for the given pod
// by scanning the statedb device table for rows with a matching PodUID.
func (driver *Driver) allocationsForPod(podUID kube_types.UID) []allocation {
	txn := driver.db.ReadTxn()
	var result []allocation
	for row := range driver.deviceTable.All(txn) {
		if row.PodUID == podUID {
			if a, ok := allocationFromRow(row); ok {
				result = append(result, a)
			}
		}
	}
	return result
}

// setAllocationInTable updates the statedb row for each device in allocs with
// the given podUID and claimUID.
func (driver *Driver) setAllocationInTable(allocs []allocation, podUID, claimUID kube_types.UID) {
	byName := allocationsByName(allocs)

	wtxn := driver.db.WriteTxn(driver.deviceTable)
	defer wtxn.Commit()

	for d := range driver.deviceTable.All(wtxn) {
		a, ok := byName[d.Name]
		if !ok {
			continue
		}

		row := d.Clone()
		row.PodUID = podUID
		row.ClaimUID = claimUID
		row.Config = a.Config
		row.Pool = a.Pool
		driver.deviceTable.Insert(wtxn, row)
	}
}

// clearAllocationInTable clears the PodUID/ClaimUID/Config fields for each
// device in allocs.
func (driver *Driver) clearAllocationInTable(allocs []allocation) {
	byName := allocationsByName(allocs)

	wtxn := driver.db.WriteTxn(driver.deviceTable)
	defer wtxn.Commit()

	for d := range driver.deviceTable.All(wtxn) {
		if _, ok := byName[d.Name]; !ok {
			continue
		}

		row := d.Clone()
		row.PodUID = ""
		row.ClaimUID = ""
		row.Config = types.DeviceConfig{}
		driver.deviceTable.Insert(wtxn, row)
	}
}

// allocationsByName builds a device-name→allocation index
// for more convenient lookups.
func allocationsByName(allocs []allocation) map[string]allocation {
	byName := make(map[string]allocation, len(allocs))
	for _, a := range allocs {
		if a.Device != nil {
			byName[a.Device.IfName()] = a
		}
	}
	return byName
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
// so pools with no devices are still published as empty slices. Pool
// membership and device attributes are resolved here, on demand,
// using the latest information present in statedb.
func (driver *Driver) buildPoolsFromTable() map[string]resourceslice.Pool {
	txn := driver.db.ReadTxn()

	sortedPools := slices.Clone(driver.config.Pools)
	slices.SortFunc(sortedPools, func(a, b v2alpha1.CiliumNetworkDriverDevicePoolConfig) int {
		return cmp.Compare(a.PoolName, b.PoolName)
	})

	pools := make(map[string]resourceslice.Pool, len(driver.config.Pools))
	for _, p := range driver.config.Pools {
		if p.Filter != nil {
			pools[p.PoolName] = resourceslice.Pool{Slices: []resourceslice.Slice{{}}}
		}
	}

	for d := range driver.deviceTable.All(txn) {
		if d.Dev == nil {
			continue
		}

		var pool string

		// if an allocation exists, the device was allocated
		// from a pool on a previous run.
		// we should stick with that pool
		// until the device is eventually unallocated
		if d.ClaimUID != "" && d.PodUID != "" {
			if d.Pool == "" {
				// pool is empty while we have allocation
				// state for this device. this shouldn't happen
				// (devices should always belong to a pool)
				// skip advertising this device to prevent
				// double allocation.
				continue
			}

			pool = d.Pool
		} else {
			pool = driver.resolvePool(d.Dev, sortedPools)
		}

		entry, ok := pools[pool]
		if !ok {
			// pool does not exist in the current configuration
			// dont advertise the device
			continue
		}

		attrs := d.Dev.GetAttrs()
		if attrs == nil {
			attrs = make(map[resourceapi.QualifiedName]resourceapi.DeviceAttribute)
		}
		attrs[resourceapi.QualifiedName(types.PoolNameLabel)] = resourceapi.DeviceAttribute{StringValue: ptr.To(pool)}
		attrs[resourceapi.QualifiedName(types.DeviceManagerLabel)] = resourceapi.DeviceAttribute{StringValue: ptr.To(d.Manager.String())}

		entry.Slices[0].Devices = append(entry.Slices[0].Devices, resourceapi.Device{
			Name:       d.Name,
			Attributes: attrs,
		})
		pools[pool] = entry
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
		Pool:    devStatus.Pool,
	}, nil
}

func (driver *Driver) restoreDevicesFromClaim(claim *resourceapi.ResourceClaim, wtxn statedb.WriteTxn) error {
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

		ifname := alloc.Device.IfName()

		// Write a row with allocation state and a fully restored Dev handle.
		// The row must exist before DRA/NRI callbacks can arrive so they
		// can look up the device by ClaimUID. A later onDevices call from
		// the device manager will merge in any live-scan updates
		// without touching allocation state.
		row := &DRADevice{
			Name:     ifname,
			Manager:  alloc.Manager,
			Dev:      alloc.Device,
			PodUID:   podUID,
			ClaimUID: claim.UID,
			Config:   alloc.Config,
			Pool:     alloc.Pool,
		}
		driver.deviceTable.Insert(wtxn, row)

		driver.logger.Debug("allocation device restored",
			logfields.PodUID, podUID,
			logfields.ClaimUID, claim.UID,
			logfields.Device, ifname,
			logfields.Config, alloc.Config,
		)
	}

	return errors.Join(errs...)
}

func (driver *Driver) restoreDevices(ctx context.Context, markRestoreDone func(statedb.WriteTxn)) error {
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

	wtxn := driver.db.WriteTxn(driver.deviceTable)
	defer wtxn.Commit()

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
		if err := driver.restoreDevicesFromClaim(claim, wtxn); err != nil {
			errs = append(errs, fmt.Errorf("failed to restore allocated devices from claim %s/%s: %w", claim.Namespace, claim.Name, err))
		}
	}

	// Mark "restore" initializer done. All restored rows are in this WriteTxn;
	// they become visible atomically when Commit() is called above (deferred).
	markRestoreDone(wtxn)

	return errors.Join(errs...)
}
