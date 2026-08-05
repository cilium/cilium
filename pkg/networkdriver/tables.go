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

// deviceByClaimUID is a secondary index over ClaimUID so that
// unprepareResourceClaim can look up all devices for a claim in O(log n)
// without scanning the full table.
var deviceByClaimUID = statedb.Index[*DRADevice, string]{
	Name: "claim-uid",
	FromObject: func(d *DRADevice) index.KeySet {
		return index.NewKeySet(index.String(string(d.ClaimUID)))
	},
	FromKey:    index.String,
	FromString: index.FromString,
	Unique:     false,
}

// DevicesByClaimUID returns all devices allocated for the given claim UID.
func DevicesByClaimUID(tbl statedb.Table[*DRADevice], txn statedb.ReadTxn, claimUID kube_types.UID) iter.Seq2[*DRADevice, statedb.Revision] {
	return tbl.List(txn, deviceByClaimUID.Query(string(claimUID)))
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
	Attrs   map[string]resourceapi.DeviceAttribute

	// Allocation fields — non-zero when the device is prepared for a pod.
	PodUID   kube_types.UID
	ClaimUID kube_types.UID
	Config   types.DeviceConfig
}

// IsAllocated reports whether the device has been prepared for a pod.
func (d *DRADevice) IsAllocated() bool { return d.PodUID != "" }

// GetAttr returns the attribute value for the given key and whether it was found.
func (d *DRADevice) GetAttr(key string) (resourceapi.DeviceAttribute, bool) {
	v, ok := d.Attrs[key]
	return v, ok
}

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
		deviceByClaimUID,
	)
}

// attrsToMap converts a device attribute map keyed by QualifiedName to a plain
// string-keyed map for storage in DRADevice.Attrs.
func attrsToMap(attrs map[resourceapi.QualifiedName]resourceapi.DeviceAttribute) map[string]resourceapi.DeviceAttribute {
	if len(attrs) == 0 {
		return nil
	}
	m := make(map[string]resourceapi.DeviceAttribute, len(attrs))
	for k, v := range attrs {
		m[string(k)] = v
	}
	return m
}
