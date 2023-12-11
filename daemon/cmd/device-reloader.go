// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"context"
	"slices"

	"github.com/cilium/cilium/pkg/datapath/tables"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/hive/job"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/promise"
	"github.com/cilium/cilium/pkg/statedb"
	"github.com/cilium/cilium/pkg/time"
)

type deviceReloaderParams struct {
	cell.In

	Jobs          job.Registry
	Scope         cell.Scope
	DB            *statedb.DB
	Daemon        promise.Promise[*Daemon]
	Config        *option.DaemonConfig
	Devices       statedb.Table[*tables.Device]
	NodeAddresses statedb.Table[tables.NodeAddress]
}

type deviceReloader struct {
	params       deviceReloaderParams
	addrsChanged <-chan struct{}
	devsChanged  <-chan struct{}
	prevDevices  []string
	jg           job.Group
}

// registerDeviceReloader provides the device reloader to the hive. The device reloader reloads the
// datapath when the runtime devices (i.e. links) change. This is a legacy component. New code
// should NOT be added here, but should directly use Table[*Device], Table[NodeAddress] or both.
//
// The current functionality of this reloader is to reload the datapath when either the node address
// or the devices change. This leads to potentially inconsistent, observable state when the device
// changes have not yet propagated to the NodeAddress changes. Components which depend on both need
// to live with this fact and come up with component-specific strategies to deal with it.
func registerDeviceReloader(lc hive.Lifecycle, p deviceReloaderParams) {
	if !p.Config.EnableRuntimeDeviceDetection {
		return
	}

	lc.Append(&deviceReloader{params: p})
}

// Start listening to changed devices if requested.
func (d *deviceReloader) Start(ctx hive.HookContext) error {
	if !d.params.Config.AreDevicesRequired() {
		log.Info("Runtime device detection requested, but no feature requires it. Disabling detection.")
		return nil
	}

	// Force an initial reload by supplying a closed channel.
	c := make(chan struct{})
	close(c)
	d.devsChanged = c

	jg := d.params.Jobs.NewGroup(d.params.Scope)
	jg.Add(job.Timer("device-reloader", d.reload, time.Second))
	d.jg = jg
	return jg.Start(ctx)
}

func (d *deviceReloader) Stop(ctx hive.HookContext) error {
	if d.jg != nil {
		return d.jg.Stop(ctx)
	}
	return nil
}

func (d *deviceReloader) query() []string {
	rxn := d.params.DB.ReadTxn()
	_, d.addrsChanged = d.params.NodeAddresses.All(rxn)

	var devices []*tables.Device
	devices, d.devsChanged = tables.SelectedDevices(d.params.Devices, rxn)
	return tables.DeviceNames(devices)
}

func (d *deviceReloader) reload(ctx context.Context) error {
	var addrsChanged bool
	select {
	case <-d.addrsChanged:
		addrsChanged = true
	case <-d.devsChanged:
	case <-ctx.Done():
		return ctx.Err()
	}

	// Note that the consumers may see inconsistent state in between updates to
	// the devices and the node addresses, but that we are eventually
	// consistent.

	// Setup new watch channels.
	devices := d.query()
	// Don't do any work if we don't need to.
	if slices.Equal(d.prevDevices, devices) && !addrsChanged {
		return nil
	}

	d.params.Config.SetDevices(devices)

	if d.params.Config.MasqueradingEnabled() && option.Config.EnableBPFMasquerade {
		if err := node.InitBPFMasqueradeAddrs(devices); err != nil {
			log.Warnf("InitBPFMasqueradeAddrs failed: %s", err)
		}
	}

	daemon, err := d.params.Daemon.Await(ctx)
	if err != nil {
		return err
	}
	if daemon.l2announcer != nil {
		daemon.l2announcer.DevicesChanged(devices)
	}

	if d.params.Config.EnableNodePort {
		// Synchronize services and endpoints to reflect new addresses onto lbmap.
		daemon.svc.SyncServicesOnDeviceChange(daemon.Datapath().LocalNodeAddressing())
		daemon.controllers.TriggerController(syncHostIPsController)
	}

	// Reload the datapath.
	wg, err := daemon.TriggerReloadWithoutCompile("devices changed")
	if err != nil {
		log.WithError(err).Warn("Failed to reload datapath")
	} else {
		wg.Wait()
	}
	d.prevDevices = devices
	return nil
}
