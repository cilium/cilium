// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package networkdriver

import (
	"iter"

	"github.com/cilium/statedb"
	"github.com/cilium/statedb/index"
	resourceapi "k8s.io/api/resource/v1"
	kube_types "k8s.io/apimachinery/pkg/types"

	"github.com/cilium/cilium/pkg/networkdriver/types"
)

// ---------------------------------------------------------------------------
// DRADevice — single table tracking every device known to the driver.
//
// A device moves through two lifecycle stages without leaving the table:
//
//  1. Discovered (IsAllocated() == false): the device manager reported it;
//     it is eligible for pool assignment and ResourceSlice publishing.
//
//  2. Allocated (IsAllocated() == true): a PrepareResourceClaims call has
//     set PodUID/ClaimUID/Config. The device is in (or on its way into) a
//     pod network namespace.
//
// Publish cycles upsert discovered devices, preserving allocation state for
// rows that are already allocated. Unprepare clears the allocation fields
// rather than deleting the row — the physical device still exists.
// ---------------------------------------------------------------------------

const DevicesTableName = "networkdriver-dra-devices"

// deviceByKey is the single primary index, keyed as "<pool>/<name>".
// This allows O(log n) prefix scans over all devices in a pool via
// DevicesByPool, without any secondary indices.
var deviceByKey = statedb.Index[*DRADevice, string]{
	Name: "id",
	FromObject: func(d *DRADevice) index.KeySet {
		return index.NewKeySet(index.String(DeviceKey(d.Pool, d.Name)))
	},
	FromKey:    index.String,
	FromString: index.FromString,
	Unique:     true,
}

// DeviceKey returns the primary key for a device.
func DeviceKey(pool, name string) string { return pool + "/" + name }

// DevicesByPool returns an iterator over all devices in the given pool.
func DevicesByPool(tbl statedb.Table[*DRADevice], txn statedb.ReadTxn, pool string) iter.Seq2[*DRADevice, statedb.Revision] {
	return tbl.Prefix(txn, deviceByKey.Query(DeviceKey(pool, "")))
}

// DRADevice represents a device known to the network driver.
// Allocation fields (PodUID, ClaimUID, Config) are zero when the device is
// unallocated; non-zero when prepared for a pod.
type DRADevice struct {
	// Name is the device name assigned by the device manager (DRADevice.IfName()).
	// It is the primary key and the name used in ResourceSlice advertisements.
	// It does not necessarily match the kernel interface name (DRADevice.KernelIfName()).
	Name    string
	Manager types.DeviceManagerType
	Dev     types.Device
	Pool    string
	Attrs   map[string]resourceapi.DeviceAttribute

	// Allocation state — zero values mean the device is free.
	PodUID   kube_types.UID
	ClaimUID kube_types.UID
	Config   types.DeviceConfig
}

// IsAllocated reports whether the device has been prepared for a pod.
func (d *DRADevice) IsAllocated() bool { return d.PodUID != "" }

func (d *DRADevice) Clone() *DRADevice {
	c := *d
	return &c
}

func (d *DRADevice) TableHeader() []string {
	return []string{"Name", "Manager", "Pool", "PodUID", "ClaimUID", "PodIfName"}
}

func (d *DRADevice) TableRow() []string {
	return []string{
		d.Name, d.Manager.String(), d.Pool,
		string(d.PodUID), string(d.ClaimUID), d.Config.PodIfName,
	}
}

func newDeviceTable(db *statedb.DB) (statedb.RWTable[*DRADevice], error) {
	return statedb.NewTable(
		db,
		DevicesTableName,
		deviceByKey,
	)
}
