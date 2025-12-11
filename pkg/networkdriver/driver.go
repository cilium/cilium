// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package networkdriver

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path"

	"github.com/blang/semver/v4"
	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/containerd/nri/pkg/stub"
	resourceapi "k8s.io/api/resource/v1"
	kube_types "k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/wait"
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
	node_types "github.com/cilium/cilium/pkg/node/types"
	"github.com/cilium/cilium/pkg/time"
)

var (
	defaultDriverPluginPath = "/var/lib/kubelet/plugins/"
)

func driverPluginPath(driverName string) string {
	return path.Join(defaultDriverPluginPath, driverName)
}

type Driver struct {
	kubeClient kubernetes.Interface
	draPlugin  *kubeletplugin.Helper
	nriPlugin  stub.Stub
	logger     *slog.Logger
	lock       lock.Mutex
	jg         job.Group

	configCRD resource.Resource[*v2alpha1.CiliumNetworkDriverConfig]
	config    *v2alpha1.CiliumNetworkDriverConfigSpec

	deviceManagers map[types.DeviceManagerType]types.DeviceManager
	// pod.UID: claim.UID: allocation
	allocations map[kube_types.UID]map[kube_types.UID][]allocation
	devices     []types.Device
}

type allocation struct {
	Device types.Device
	Config types.DeviceConfig
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
		if p.Filter == nil {
			// no filter specified, this shouldn't happen
			driver.logger.ErrorContext(
				ctx, "pool filter is missing. not handling this pool",
				logfields.PoolName, p.PoolName,
			)

			continue
		}

		filtered := filterDevices(driver.devices, *p.Filter)

		var devices []resourceapi.Device

		for _, dev := range filtered {
			if dev.IfName() == "" {
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

// watchConfig blocks forever until a configuration is found (from the CRD).
func (driver *Driver) watchConfig(ctx context.Context) error {
	var (
		errChannelClosed    = errors.New("channel closed")
		errContextCancelled = errors.New("context cancelled")
	)

	for {
		select {
		case <-ctx.Done():
			return fmt.Errorf("%w: %w", errContextCancelled, ctx.Err())
		case ev, ok := <-driver.configCRD.Events(ctx):
			if !ok {
				return errChannelClosed
			}

			defer ev.Done(nil)

			switch ev.Kind {
			case resource.Sync:
				driver.logger.DebugContext(ctx, "configuration sync received")
			case resource.Delete:
				driver.logger.DebugContext(ctx, "configuration delete received")
			case resource.Upsert:
				driver.logger.DebugContext(ctx, "configuration upsert received")
			}

			if ev.Object != nil {
				newConfig := ev.Object
				if driver.config != nil {
					// if we already have a config
					driver.logger.DebugContext(
						ctx, "config received, but we already have one",
					)
				} else {
					driver.config = &newConfig.Spec
				}

				return nil
			}
		}
	}
}

// Start retrieves nadvalidates the configuration. If configuration is found and valid, it
// initializes all the devicemanagers that are enabled by config, and starts the DRA + NRI registration.
func (driver *Driver) Start(ctx cell.HookContext) error {
	driver.jg.Add(job.OneShot("network-driver", func(ctx context.Context, _ cell.Health) error {

		if version.Version().LT(semver.Version{Major: 1, Minor: 34}) {
			driver.logger.InfoContext(
				ctx, "Cilium Network Driver requires Kubernetes v1.34 or later",
				logfields.K8sAPIVersion, version.Version(),
			)

			return nil
		}

		driver.logger.DebugContext(
			ctx, "Starting network driver...",
			logfields.K8sAPIVersion, version.Version(),
		)

		err := driver.watchConfig(ctx)
		if err != nil {
			return err
		}

		if driver.config == nil {
			// not found, we wont start the driver
			driver.logger.DebugContext(
				ctx, "Network Driver configuration not found",
			)

			return nil
		}

		driver.logger.DebugContext(
			ctx, "network driver configuration found",
			logfields.DriverName, driver.config.DriverName,
		)

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

		driver.logger.DebugContext(
			ctx, "starting driver",
			logfields.DriverName, driver.config.DriverName,
		)

		// create path for our driver plugin socket.
		err = os.MkdirAll(driverPluginPath(driver.config.DriverName), 0750)
		if err != nil {
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

		// register the NRI plugin
		nriOptions := []stub.Option{
			stub.WithPluginName(driver.config.DriverName),
			stub.WithPluginIdx("00"),
			// https://github.com/containerd/nri/pull/173
			// Otherwise it silently exits the program
			stub.WithOnClose(func() {
				driver.logger.WarnContext(
					ctx, "NRI plugin closed",
					logfields.DriverName, driver.config.DriverName,
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
						logfields.Name, driver.config.DriverName,
					)
				}
				select {
				case <-ctx.Done():
					return nil
				case <-time.After(time.Second):
					driver.logger.DebugContext(ctx, "Restarting NRI plugin", logfields.Name, driver.config.DriverName)
				}
			}
		}))

		trigger := job.NewTrigger()

		driver.jg.Add(
			job.Timer(
				"networkdriver-dra-publish-resources",
				driver.publish,
				time.Duration(driver.config.PublishIntervalSeconds)*time.Second,
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
