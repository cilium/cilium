// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package networkdriver

import (
	"context"
	"errors"
	"net/netip"

	"github.com/vishvananda/netlink"

	"github.com/cilium/cilium/pkg/datapath/loader"
	"github.com/cilium/cilium/pkg/ipam"
	"github.com/cilium/cilium/pkg/networkdriver/rxqueue"
)

var (
	resetLeasedRXQueueFlows = rxqueue.ResetLeasedRXQueueFlows
	rxQueueRevokeForIP      = (*rxqueue.RXQueueDevice).RevokeRXQueueForIP
)

// rxQueueAddressGuard also runs when Network Driver configuration is absent:
// the kernel may still have leases and NIC rules from the previous agent.
type rxQueueAddressGuard struct {
	driver *Driver
}

func (*rxQueueAddressGuard) Initialize(ctx context.Context) error {
	return resetLeasedRXQueueFlows(ctx, func(device netlink.Link) (bool, error) {
		return loader.DeviceHasSKBProgramLoaded(device.Attrs().Name, false)
	})
}

func (g *rxQueueAddressGuard) BeforeRelease(address netip.Addr, _ ipam.Pool) error {
	if g.driver == nil {
		return nil
	}
	driver := g.driver
	// IPAM holds its allocation mutex. Wait only for binding, not driver.lock,
	// which DRA preparation holds across Kubernetes API calls.
	driver.rxQueueBindLock.Lock()
	defer driver.rxQueueBindLock.Unlock()
	var errs []error
	for row := range driver.allocationTable.All(driver.db.ReadTxn()) {
		device, ok := row.PreparedDevice.(*rxqueue.RXQueueDevice)
		if !ok {
			continue
		}
		unbound, err := rxQueueRevokeForIP(device, address)
		if unbound != nil {
			// Unprepare/reprepare can replace the allocation during cleanup.
			// Publish only if it still contains the device snapshot we revoked.
			wtxn := driver.db.WriteTxn(driver.allocationTable)
			key := AllocationKey(row.LogicalPool, row.DeviceName, row.ShareID)
			current, _, found := driver.allocationTable.Get(wtxn, allocationByKey.Query(key))
			if found && current.PreparedDevice == device {
				updated := current.Clone()
				updated.PreparedDevice = unbound
				driver.allocationTable.Insert(wtxn, updated)
			}
			wtxn.Commit()
		}
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}
