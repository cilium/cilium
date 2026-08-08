// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package networkdriver

import (
	"iter"

	"github.com/cilium/statedb"
	"github.com/cilium/statedb/index"
	"github.com/cilium/statedb/part"
	resourceapi "k8s.io/api/resource/v1"
	kube_types "k8s.io/apimachinery/pkg/types"

	"github.com/cilium/cilium/pkg/networkdriver/types"
)

// ---------------------------------------------------------------------------
// DRADevice — single table tracking every device discovered by the driver.
//
// The table is populated by device manager goroutines via onDevices and
// reflects both discovery state and allocation state:
//
//   - Discovery fields (Name, Manager, Dev, Pool, Attrs) are always populated
//     by onDevices whenever the device manager reports a device.
//
//   - Allocation fields (PodUID, ClaimUID, Config) are set by commitAllocation
//     when the kubelet calls PrepareResourceClaims, and cleared by
//     unprepareResourceClaim when the kubelet calls UnprepareResourceClaims.
//     On agent restart, onDevices repopulates the allocation fields from the
//     in-memory allocations map (which was itself restored from ResourceClaim
//     status by restoreDevices).
//
// The table is therefore the single observable source of truth for "which pod
// holds which device" and is visible via `cilium-dbg statedb dump`.
// ---------------------------------------------------------------------------

func init() {
	// resourceapi.QualifiedName is a named string type distinct from string itself,
	// so part's built-in string registration does not cover it. Register it here,
	// collocated with the only place in the codebase that uses it as a Map key
	// (attrsToPartMap). If QualifiedName were ever used as a part.Map key elsewhere
	// in a package that does not import networkdriver, a similar init() would be
	// needed there too.
	part.RegisterKeyType[resourceapi.QualifiedName](func(q resourceapi.QualifiedName) []byte {
		return []byte(q)
	})
}

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
//
// Discovery fields (Name, Manager, Dev, Pool, Attrs) are always present.
// Allocation fields (PodUID, ClaimUID, Config) are non-zero when the device
// has been prepared for a pod via PrepareResourceClaims, and are cleared by
// UnprepareResourceClaims. On agent restart they are restored from the
// ResourceClaim status via restoreDevices, then written back to the table
// when the device manager goroutine calls onDevices for the first time.
type DRADevice struct {
	// Name is the device name assigned by the device manager.
	// It is the primary key and the name used in ResourceSlice advertisements.
	// It does not necessarily match the kernel interface name.
	Name    string
	Manager types.DeviceManagerType
	Dev     types.Device
	Pool    string
	Attrs   part.Map[resourceapi.QualifiedName, resourceapi.DeviceAttribute]

	// Allocation fields — non-zero when the device is prepared for a pod.
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

// attrsToPartMap converts a device attribute map into a part.Map.
func attrsToPartMap(attrs map[resourceapi.QualifiedName]resourceapi.DeviceAttribute) part.Map[resourceapi.QualifiedName, resourceapi.DeviceAttribute] {
	var m part.Map[resourceapi.QualifiedName, resourceapi.DeviceAttribute]
	for k, v := range attrs {
		m = m.Set(k, v)
	}
	return m
}
