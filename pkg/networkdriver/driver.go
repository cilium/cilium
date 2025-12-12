// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package networkdriver

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path"
	"path/filepath"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/containerd/nri/pkg/stub"
	"github.com/google/renameio/v2"
	resourceapi "k8s.io/api/resource/v1"
	kube_types "k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
	"k8s.io/dynamic-resource-allocation/kubeletplugin"
	"k8s.io/dynamic-resource-allocation/resourceslice"
	"k8s.io/utils/ptr"

	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/networkdriver/devicemanagers"
	"github.com/cilium/cilium/pkg/networkdriver/dummy"
	"github.com/cilium/cilium/pkg/networkdriver/sriov"
	"github.com/cilium/cilium/pkg/networkdriver/types"
	node_types "github.com/cilium/cilium/pkg/node/types"
	"github.com/cilium/cilium/pkg/time"
)

const (
	defaultDriverPluginPath    = "/var/lib/kubelet/plugins/"
	defaultDriverStoreFileName = "network-driver-state.json"
)

func driverPluginPath(driverName string) string {
	return path.Join(defaultDriverPluginPath, driverName)
}

type Driver struct {
	driverName string
	kubeClient kubernetes.Interface
	draPlugin  *kubeletplugin.Helper
	nriPlugin  stub.Stub
	logger     *slog.Logger
	lock       lock.Mutex
	jg         job.Group

	config   Config
	stateDir string
	filePath string

	deviceManagers map[types.DeviceManagerType]types.DeviceManager
	// pod.UID: claim.UID: allocation
	allocations map[kube_types.UID]map[kube_types.UID][]allocation
	devices     []types.Device
}

type allocation struct {
	Device types.Device
	Config types.DeviceConfig
}

func (a allocation) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Type   string
		Device types.Device
		Config types.DeviceConfig
	}{
		Type:   a.Device.Type(),
		Device: a.Device,
		Config: a.Config,
	})
}

func (a *allocation) UnmarshalJSON(data []byte) error {
	var objmap map[string]json.RawMessage

	if err := json.Unmarshal(data, &objmap); err != nil {
		return fmt.Errorf("failed to unmarshal allocation: %w", err)
	}

	rawType, ok := objmap["Type"]
	if !ok {
		return errors.New("allocation type not found")
	}
	var typ string
	if err := json.Unmarshal(rawType, &typ); err != nil {
		return fmt.Errorf("failed to unmarshal allocation type: %w", err)
	}

	rawDev, ok := objmap["Device"]
	if !ok {
		return errors.New("allocation device not found")
	}
	var (
		dev types.Device
		err error
	)
	switch typ {
	case dummy.DummyDevice{}.Type():
		var dummyDev dummy.DummyDevice
		err = json.Unmarshal(rawDev, &dummyDev)
		dev = &dummyDev
	case sriov.PciDevice{}.Type():
		var pciDev sriov.PciDevice
		err = json.Unmarshal(rawDev, &pciDev)
		dev = &pciDev
	default:
		return fmt.Errorf("unknown device type: %s", typ)
	}
	if err != nil {
		return fmt.Errorf("failed to unmarshal allocation device: %w", err)
	}

	rawCfg, ok := objmap["Config"]
	if !ok {
		return errors.New("allocation config not found")
	}
	var cfg types.DeviceConfig
	if err := json.Unmarshal(rawCfg, &cfg); err != nil {
		return fmt.Errorf("failed to unmarshal allocation config: %w", err)
	}

	a.Device = dev
	a.Config = cfg

	return nil
}

func (driver *Driver) withLock(f func() error) error {
	driver.lock.Lock()
	defer driver.lock.Unlock()

	return f()
}

// filterDevices returns the resulting devices after applying a filter.
func filterDevices(devices []types.Device, filter types.DeviceFilter) []types.Device {
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
	driver.devices = nil

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

			driver.devices = append(driver.devices, devices...)
		}
	}

	pools := make(map[string]resourceslice.Pool, len(driver.config.Pools))

	for _, p := range driver.config.Pools {
		filtered := filterDevices(driver.devices, p.Filter)

		var devices []resourceapi.Device

		for _, dev := range filtered {
			if dev.IfName() == "" {
				continue
			}

			attrs := dev.GetAttrs()
			attrs["pool"] = resourceapi.DeviceAttribute{StringValue: ptr.To(p.Name)}
			devices = append(devices, resourceapi.Device{
				Name:       dev.IfName(),
				Attributes: attrs,
			})
		}

		driver.logger.DebugContext(
			ctx, "devices matched filter for pool",
			logfields.PoolName, p.Name,
			logfields.Devices, filtered,
		)

		pools[p.Name] = resourceslice.Pool{
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

// Start validates the configuration file and initializes all the devicemanagers
// that are enabled by config, and starts the DRA + NRI registration.
func (driver *Driver) Start(ctx cell.HookContext) error {
	driver.jg.Add(job.OneShot("network-driver", func(ctx context.Context, _ cell.Health) error {

		driver.logger.DebugContext(ctx, "Starting network driver...")

		if err := driver.config.Validate(); err != nil {
			return fmt.Errorf("invalid config: %w", err)
		}

		for manager, managerCfg := range driver.config.DeviceManagerConfigs {
			if !managerCfg.IsEnabled() {
				continue
			}

			d, err := devicemanagers.InitManager(driver.logger, manager, managerCfg)
			if err != nil {
				driver.logger.DebugContext(ctx,
					"failed to enable manager",
					logfields.Type, manager,
					logfields.Error, err,
				)

				return err
			}

			driver.logger.DebugContext(ctx, "enabled manager", logfields.Type, manager)
			driver.deviceManagers[manager] = d
		}

		driver.logger.DebugContext(ctx,
			"starting driver with config",
			logfields.Config, driver.config)

		// reload state from previous run, if present
		if err := driver.reloadState(); err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				driver.logger.InfoContext(ctx, "no previous network driver allocations found")
			} else {
				driver.logger.ErrorContext(ctx,
					"failed to reload previous allocations from persistent storage, resources allocated in previous runs might be leaked",
					logfields.Path, driver.filePath,
					logfields.Error, err,
				)
			}
		}

		// create path for our driver plugin socket.
		err := os.MkdirAll(driverPluginPath(driver.driverName), 0750)
		if err != nil {
			return fmt.Errorf("failed to create plugin path %s: %w", driverPluginPath(driver.driverName), err)
		}

		pluginOpts := []kubeletplugin.Option{
			kubeletplugin.DriverName(driver.driverName),
			kubeletplugin.NodeName(node_types.GetName()),
			kubeletplugin.KubeClient(driver.kubeClient),
		}

		p, err := kubeletplugin.Start(ctx, driver, pluginOpts...)
		if err != nil {
			return err
		}

		driver.draPlugin = p

		err = wait.PollUntilContextTimeout(
			ctx, driver.config.DraRegistrationRetry, driver.config.DraRegistrationTimeout, true,
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
			logfields.DriverName, driver.driverName,
		)

		// register the NRI plugin
		nriOptions := []stub.Option{
			stub.WithPluginName(driver.driverName),
			stub.WithPluginIdx("00"),
			// https://github.com/containerd/nri/pull/173
			// Otherwise it silently exits the program
			stub.WithOnClose(func() {
				driver.logger.WarnContext(
					ctx, "NRI plugin closed",
					logfields.DriverName, driver.driverName,
				)
			}),
		}

		nriStub, err := stub.New(driver, nriOptions...)
		if err != nil {
			return fmt.Errorf("failed to create plugin stub: %w", err)
		}

		driver.nriPlugin = nriStub

		driver.jg.Add(job.OneShot("networkdriver-nri-plugin-run", func(ctx context.Context, _ cell.Health) error {
			for {
				if err := driver.nriPlugin.Run(ctx); err != nil {
					driver.logger.ErrorContext(
						ctx, "NRI plugin failed",
						logfields.Error, err,
						logfields.Name, driver.driverName,
					)
				}
				select {
				case <-ctx.Done():
					return nil
				case <-time.After(time.Second):
					driver.logger.DebugContext(ctx, "Restarting NRI plugin", logfields.Name, driver.driverName)
				}
			}
		}))

		trigger := job.NewTrigger()

		driver.jg.Add(
			job.Timer(
				"networkdriver-dra-publish-resources",
				driver.publish,
				driver.config.PublishInterval,
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

func (driver *Driver) storeState() error {
	storePath := filepath.Join(driver.stateDir, defaultDriverStoreFileName)

	return driver.withLock(func() error {
		data, err := json.Marshal(driver.allocations)
		if err != nil {
			return fmt.Errorf("failed to marshal driver state: %w", err)
		}

		state, err := renameio.TempFile(driver.stateDir, storePath)
		if err != nil {
			return fmt.Errorf("failed to open temporary file to update driver state: %w", err)
		}
		defer state.Cleanup()

		if _, err := state.Write(data); err != nil {
			return fmt.Errorf("failed to write updated driver state: %w", err)
		}

		if err := state.CloseAtomicallyReplace(); err != nil {
			return fmt.Errorf("failed to atomically update driver state: %w", err)
		}

		return nil
	})
}

func (driver *Driver) reloadState() error {
	data, err := os.ReadFile(driver.filePath)
	if err != nil {
		return fmt.Errorf("failed to read driver state: %w", err)
	}

	return driver.withLock(func() error {
		return json.Unmarshal(data, &driver.allocations)
	})
}
