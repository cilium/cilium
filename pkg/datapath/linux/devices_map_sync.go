// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build linux

package linux

import (
	"context"
	"log/slog"
	"net"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/cilium/statedb"

	"github.com/cilium/cilium/pkg/datapath/tables"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/maps/devicesmap"
	"github.com/cilium/cilium/pkg/rate"
	"github.com/cilium/cilium/pkg/time"
)

// DevicesMapSyncCell keeps the cilium_devices map in sync with the selected devices.
var DevicesMapSyncCell = cell.Module(
	"devices-map-sync",
	"Synchronizes device state into the cilium_devices BPF map",
	cell.Invoke(registerDevicesMapSync),
)

type devicesMapSyncParams struct {
	cell.In

	JobGroup  job.Group
	Logger    *slog.Logger
	DB        *statedb.DB
	Devices   statedb.Table[*tables.Device]
	DeviceMap devicesmap.Map
}

func registerDevicesMapSync(p devicesMapSyncParams) {
	p.JobGroup.Add(job.OneShot(
		"devices-map-sync",
		func(ctx context.Context, _ cell.Health) error {
			return syncDevicesMap(p, ctx)
		},
	))
}

func syncDevicesMap(p devicesMapSyncParams, ctx context.Context) error {
	limiter := rate.NewLimiter(50*time.Millisecond, 1)
	defer limiter.Stop()

	ticker := time.NewTicker(time.Minute * 5)
	defer ticker.Stop()

	for {
		rx := p.DB.ReadTxn()
		devices, watch := tables.SelectedDevices(p.Devices, rx)
		desired := desiredState(devices)

		upsertDesiredDevices(p, desired)
		pruneStaleDevices(p, desired)

		select {
		case <-watch:
		case <-ticker.C:
		case <-ctx.Done():
			return ctx.Err()
		}
		if err := limiter.Wait(ctx); err != nil {
			return err
		}
	}
}

func desiredState(devices []*tables.Device) map[uint32]devicesmap.DeviceState {
	desired := make(map[uint32]devicesmap.DeviceState, len(devices))
	for _, dev := range devices {
		desired[uint32(dev.Index)] = devicesmap.NewDeviceState(net.HardwareAddr(dev.HardwareAddr))
	}
	return desired
}

func pruneStaleDevices(p devicesMapSyncParams, desired map[uint32]devicesmap.DeviceState) {
	var stale []uint32
	err := p.DeviceMap.IterateWithCallback(func(key *devicesmap.DeviceKey, _ *devicesmap.DeviceState) {
		if _, ok := desired[key.IfIndex]; ok {
			return
		}
		stale = append(stale, key.IfIndex)
	})
	if err != nil {
		p.Logger.Warn("Failed to iterate device map", logfields.Error, err)
	}
	for _, ifindex := range stale {
		if err := p.DeviceMap.Delete(ifindex); err != nil {
			p.Logger.Warn("Failed to delete stale device map entry",
				logfields.Error, err,
				logfields.Interface, ifindex,
			)
		}
	}
}

func upsertDesiredDevices(p devicesMapSyncParams, desired map[uint32]devicesmap.DeviceState) {
	for ifindex, state := range desired {
		if err := p.DeviceMap.Upsert(ifindex, state); err != nil {
			p.Logger.Warn("Failed to upsert device map entry",
				logfields.Error, err,
				logfields.Interface, ifindex,
			)
		}
	}
}
