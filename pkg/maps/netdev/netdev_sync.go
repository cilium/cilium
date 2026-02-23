// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build linux

package netdev

import (
	"context"
	"log/slog"
	"net"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/cilium/statedb"

	"github.com/cilium/cilium/pkg/datapath/tables"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/rate"
	"github.com/cilium/cilium/pkg/time"
)

// NetDevMapSyncCell keeps the cilium_devices map in sync with the selected devices.
var NetDevMapSyncCell = cell.Module(
	"netdev-map-sync",
	"Synchronizes network devices state into the cilium_devices BPF map",
	cell.Invoke(registerNetDevMapSync),
)

type netDevMapSyncParams struct {
	cell.In

	JobGroup  job.Group
	Logger    *slog.Logger
	DB        *statedb.DB
	Devices   statedb.Table[*tables.Device]
	DeviceMap Map
}

func registerNetDevMapSync(p netDevMapSyncParams) {
	p.JobGroup.Add(job.OneShot(
		"netdev-map-sync",
		func(ctx context.Context, _ cell.Health) error {
			return syncNetDevMap(p, ctx)
		},
	))
}

func syncNetDevMap(p netDevMapSyncParams, ctx context.Context) error {
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

func desiredState(devices []*tables.Device) map[uint32]DeviceState {
	desired := make(map[uint32]DeviceState, len(devices))
	for _, dev := range devices {
		desired[uint32(dev.Index)] = NewDeviceState(net.HardwareAddr(dev.HardwareAddr))
	}
	return desired
}

func pruneStaleDevices(p netDevMapSyncParams, desired map[uint32]DeviceState) {
	var stale []uint32
	err := p.DeviceMap.IterateWithCallback(func(k *Index, _ *DeviceState) {
		key := uint32(*k)
		if _, ok := desired[key]; ok {
			return
		}
		stale = append(stale, key)
	})
	if err != nil {
		p.Logger.Warn("Failed to iterate network devices map", logfields.Error, err)
	}
	for _, ifindex := range stale {
		if err := p.DeviceMap.Clear(ifindex); err != nil {
			p.Logger.Warn("Failed to clear stale network devices map entry",
				logfields.Error, err,
				logfields.Interface, ifindex,
			)
		}
	}
}

func upsertDesiredDevices(p netDevMapSyncParams, desired map[uint32]DeviceState) {
	for ifindex, state := range desired {
		if err := p.DeviceMap.Upsert(ifindex, state); err != nil {
			p.Logger.Warn("Failed to upsert network devices map entry",
				logfields.Error, err,
				logfields.Interface, ifindex,
			)
		}
	}
}
