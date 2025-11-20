// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package dra

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/containerd/nri/pkg/stub"
	resourceapi "k8s.io/api/resource/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/dynamic-resource-allocation/kubeletplugin"
	"k8s.io/dynamic-resource-allocation/resourceslice"

	"github.com/cilium/cilium/pkg/defaults"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/logging/logfields"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
)

const (
	driverName  = "cilium-dra-driver"
	pluginIndex = "00"

	draRegistrationRetry   = time.Second
	draRegistrationTimeout = 30 * time.Second

	resourcesProbeInterval = 3 * time.Second
)

// DevicesLister is anything that knows how to list devices and return them as a slice of resourceapi.Device.
type DevicesLister func(
	ctx context.Context,
	logger *slog.Logger,
	toQualifiedName func(string) resourceapi.QualifiedName,
) ([]resourceapi.Device, error)

// Driver is the core structure of the DRA driver.
type Driver struct {
	logger    *slog.Logger
	cs        k8sClient.Clientset
	jg        job.Group
	name      string
	nodeName  string
	draPlugin *kubeletplugin.Helper
	nriPlugin stub.Stub

	lock            sync.Mutex
	podDeviceConfig map[types.UID][]AllocatedDevice // maps pod UID to allocated devices with attributes

	listDevices DevicesLister
}

func registerDRA(lc cell.Lifecycle, logger *slog.Logger, cs k8sClient.Clientset, jg job.Group) {
	driver := &Driver{
		logger:          logger,
		cs:              cs,
		jg:              jg,
		name:            driverName,
		nodeName:        nodeTypes.GetName(),
		podDeviceConfig: make(map[types.UID][]AllocatedDevice),
	}

	// TODO: customize this based on driver config
	driver.listDevices = func(
		ctx context.Context,
		logger *slog.Logger,
		toQualifiedName func(string) resourceapi.QualifiedName,
	) ([]resourceapi.Device, error) {
		return nil, nil
	}

	lc.Append(driver)
}

func (driver *Driver) Start(ctx cell.HookContext) error {
	// create path for the driver plugin socket
	driverPluginPath := filepath.Join(kubeletplugin.KubeletPluginsDir, driver.name)
	if err := os.MkdirAll(driverPluginPath, defaults.RuntimePathRights); err != nil {
		return fmt.Errorf("failed to create DRA plugin path %s: %w", driverPluginPath, err)
	}

	driver.jg.Add(job.OneShot("dra-driver-init", driver.init))

	return nil
}

func (driver *Driver) init(ctx context.Context, _ cell.Health) error {
	// register the DRA plugin
	draHelper, err := kubeletplugin.Start(
		ctx, driver,
		kubeletplugin.DriverName(driver.name),
		kubeletplugin.NodeName(driver.nodeName),
		kubeletplugin.KubeClient(driver.cs),
	)
	if err != nil {
		return fmt.Errorf("kubelet plugin start failed: %w", err)
	}
	driver.draPlugin = draHelper

	if err := wait.PollUntilContextTimeout(
		ctx, draRegistrationRetry, draRegistrationTimeout, true,
		func(context.Context) (bool, error) {
			registrationStatus := driver.draPlugin.RegistrationStatus()
			if registrationStatus == nil {
				return false, nil
			}
			return registrationStatus.PluginRegistered, nil
		}); err != nil {
		return fmt.Errorf("DRA plugin registration failed: %w", err)
	}

	// register the NRI plugin
	nriStub, err := stub.New(
		driver,
		stub.WithPluginName(driver.name),
		stub.WithPluginIdx(pluginIndex),
		// see https://github.com/containerd/nri/pull/173
		stub.WithOnClose(func() {
			driver.logger.InfoContext(ctx, "NRI plugin closed", logfields.Name, driver.name)
		}),
	)
	if err != nil {
		return fmt.Errorf("failed to create NRI plugin stub: %w", err)
	}
	driver.nriPlugin = nriStub

	driver.jg.Add(job.OneShot("dra-nri-plugin-run", func(ctx context.Context, _ cell.Health) error {
		for {
			if err := driver.nriPlugin.Run(ctx); err != nil {
				driver.logger.ErrorContext(ctx, "NRI plugin failed", logfields.Error, err, logfields.Name, driver.name)
			}
			select {
			case <-ctx.Done():
				return nil
			default:
				driver.logger.InfoContext(ctx, "Restarting NRI plugin", logfields.Name, driver.name)
			}
		}
	}))
	driver.jg.Add(job.OneShot("dra-publish-resources", driver.publishResources))

	return nil
}

func (driver *Driver) Stop(ctx cell.HookContext) error {
	driver.nriPlugin.Stop()
	driver.draPlugin.Stop()
	return nil
}

func (driver *Driver) publishResources(ctx context.Context, _ cell.Health) error {
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(resourcesProbeInterval):
			devices, err := driver.listDevices(ctx, driver.logger, driver.toQualifiedName)
			if err != nil {
				driver.logger.ErrorContext(ctx, "Failed to list devices", logfields.Error, err)
				continue
			}

			resources := resourceslice.DriverResources{
				Pools: map[string]resourceslice.Pool{
					driver.nodeName: {Slices: []resourceslice.Slice{{Devices: devices}}},
				},
			}

			if err := driver.draPlugin.PublishResources(ctx, resources); err != nil {
				driver.logger.ErrorContext(ctx, "Failed to publish resources", logfields.Error, err)
				continue
			}
			driver.logger.InfoContext(ctx, "Published network devices", logfields.NumDevices, len(devices))
		}
	}
}

func (driver *Driver) toQualifiedName(attr string) resourceapi.QualifiedName {
	return resourceapi.QualifiedName(driver.name + "/" + attr)
}
