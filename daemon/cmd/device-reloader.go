// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"context"
	"fmt"
	"slices"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/cilium/statedb"
	"github.com/vishvananda/netlink"
	"k8s.io/apimachinery/pkg/util/sets"

	"github.com/cilium/cilium/pkg/datapath/tables"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/promise"
	"github.com/cilium/cilium/pkg/rate"
	"github.com/cilium/cilium/pkg/time"
)

type deviceReloaderParams struct {
	cell.In

	Jobs          job.Registry
	Health        cell.Health
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
	limiter      *rate.Limiter
}

// registerDeviceReloader provides the device reloader to the hive. The device reloader reloads the
// datapath when the runtime devices (i.e. links) change. This is a legacy component. New code
// should NOT be added here, but should directly use Table[*Device], Table[NodeAddress] or both.
//
// The current functionality of this reloader is to reload the datapath when either the node address
// or the devices change. This leads to potentially inconsistent, observable state when the device
// changes have not yet propagated to the NodeAddress changes. Components which depend on both need
// to live with this fact and come up with component-specific strategies to deal with it.
func registerDeviceReloader(lc cell.Lifecycle, p deviceReloaderParams) {
	lc.Append(&deviceReloader{params: p})
}

// Start listening to changed devices if requested.
func (d *deviceReloader) Start(ctx cell.HookContext) error {
	// Force an initial reload by supplying a closed channel.
	c := make(chan struct{})
	close(c)
	d.addrsChanged = c

	d.limiter = rate.NewLimiter(time.Millisecond*500, 1)

	jg := d.params.Jobs.NewGroup(d.params.Health)
	jg.Add(job.Timer("device-reloader", d.reload, time.Second))
	d.jg = jg
	return jg.Start(ctx)
}

func (d *deviceReloader) Stop(ctx cell.HookContext) error {
	if d.jg != nil {
		return d.jg.Stop(ctx)
	}
	return nil
}

func (d *deviceReloader) queryDevices(rxn statedb.ReadTxn) []string {
	var nativeDevices []*tables.Device
	nativeDevices, d.devsChanged = tables.SelectedDevices(d.params.Devices, rxn)
	fmt.Println("[tom-debug] queryDevices: ", tables.DeviceNames(nativeDevices))
	return tables.DeviceNames(nativeDevices)
}

func (d *deviceReloader) reload(ctx context.Context) error {
	fmt.Println("[tom-debug] device reloader reload --->")
	var addrsChanged bool
	select {
	case <-d.addrsChanged:
		addrsChanged = true
	case <-d.devsChanged:
	case <-ctx.Done():
		return ctx.Err()
	}

	// Rate-limit to avoid reinitializing too often and to allow NodeAddress table
	// to update.
	if err := d.limiter.Wait(ctx); err != nil {
		return err
	}

	// Note that the consumers may see inconsistent state in between updates to
	// the devices and the node addresses, but that we are eventually
	// consistent.

	// Setup new watch channels.
	rxn := d.params.DB.ReadTxn()
	if addrsChanged {
		_, d.addrsChanged = d.params.NodeAddresses.AllWatch(rxn)
	}
	devices := d.queryDevices(rxn)

	prev := sets.New[string](d.prevDevices...)
	curr := sets.New[string](devices...)

	for added := range curr.Difference(prev) {
		fmt.Println("[tom-debug] device reloader detected added:", added)
	}
	for missing := range prev.Difference(curr) {
		fmt.Println("[tom-debug] device reloader detected missing:", missing)
	}
	// Don't do any work if we don't need to.
	if slices.Equal(d.prevDevices, devices) && !addrsChanged {
		return nil
	}

	DumpLinks("pre daemon await")

	daemon, err := d.params.Daemon.Await(ctx)
	if err != nil {
		return err
	}

	DumpLinks("trigger reload")
	// Reload the datapath.
	wg, err := daemon.TriggerReload("devices changed")
	if err != nil {
		log.WithError(err).Warn("Failed to reload datapath")
	} else {
		wg.Wait()
	}

	DumpLinks("post-reload")
	d.prevDevices = devices
	fmt.Println("[tom-debug] setting prevDevices to: ", d.prevDevices)
	return nil
}

func DumpLinks(tag string) {
	tag += " [device-reloader]"
	fmt.Println(tag, "[tom-debug] #### tracing endpoint links ####")
	links, err := netlink.LinkList()
	if err != nil {
		fmt.Println(tag, "[tom-debug] error listing links:", err)
		return
	}
	found := false
	for _, link := range links {
		if link.Attrs().Name == "lxc_health" {
			fmt.Println(tag, "[tom-debug] link:", link.Attrs().Name, link.Attrs().Index)
			found = true
		}
	}
	if !found {
		fmt.Println("[tom-debug] Link not found here!!!! #######################")
	}
	fmt.Println(tag, "[tom-debug] #### trace done ####")
}
