// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package mtu

import (
	"context"
	"fmt"
	"slices"

	"github.com/cilium/cilium/pkg/datapath/tables"
	"github.com/cilium/cilium/pkg/defaults"

	"github.com/cilium/hive/cell"
)

type MTUManager struct {
	mtuParams
	Config *Configuration
}

// The MTU on these devices is set by us indirectly, so we don't want to
// use them as source for MTU detection since that would create a loop.
var excludedDevices = []string{
	defaults.VxlanDevice,
	defaults.GeneveDevice,
	defaults.IPIPv4Device,
	defaults.IPIPv6Device,
}

func (m *MTUManager) Updater(ctx context.Context, health cell.Health) error {
	for {
		devs, devsChanged := tables.SelectedDevices(m.Devices, m.DB.ReadTxn())

		baseMTU := MaxMTU
		for _, dev := range devs {
			if slices.Contains(excludedDevices, dev.Name) {
				continue
			}

			baseMTU = min(baseMTU, dev.MTU)
		}

		routeMTU := m.Config.Calculate(baseMTU)

		txn := m.DB.WriteTxn(m.MTUTable)

		changed := false

		// Update the IPv4 default route MTU if it has changed
		existing, _, found := m.MTUTable.Get(txn, MTURouteIndex.Query(DefaultPrefixV4))
		if !found || existing.DeviceMTU != routeMTU.DeviceMTU {
			routeMTU.Prefix = DefaultPrefixV4
			_, _, err := m.MTUTable.Insert(txn, routeMTU)
			if err != nil {
				txn.Abort()
				return err
			}
			changed = true
		}

		// Update the IPv6 default route MTU if it has changed
		existing, _, found = m.MTUTable.Get(txn, MTURouteIndex.Query(DefaultPrefixV6))
		if !found || existing.DeviceMTU != routeMTU.DeviceMTU {
			routeMTU.Prefix = DefaultPrefixV6
			_, _, err := m.MTUTable.Insert(txn, routeMTU)
			if err != nil {
				txn.Abort()
				return err
			}
			changed = true
		}

		txn.Commit()

		if changed {
			health.OK(fmt.Sprintf("MTU updated (%d)", routeMTU.DeviceMTU))
		}

		select {
		case <-ctx.Done():
			return nil
		case <-devsChanged:
		}
	}
}
