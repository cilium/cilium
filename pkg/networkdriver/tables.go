// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package networkdriver

import (
	"iter"

	"github.com/cilium/statedb"
	"github.com/cilium/statedb/index"
	kube_types "k8s.io/apimachinery/pkg/types"

	"github.com/cilium/cilium/pkg/networkdriver/types"
)

// ---------------------------------------------------------------------------
// DRADevice — single table tracking every device discovered by the driver.
//
// The table is populated by device manager goroutines via onDevices and
// reflects both discovery state and allocation state:
//
//   - Discovery fields (Name, Manager, Dev) are always populated by onDevices
//     whenever the device manager reports a device.
//
//   - Allocation fields (PodUID, ClaimUID, Config) are set by setAllocationInTable
//     when the kubelet calls PrepareResourceClaims, and cleared by
//     unprepareResourceClaim when the kubelet calls UnprepareResourceClaims.
//     On agent restart, restoreDevices repopulates these fields (and the Dev
//     handle) directly from ResourceClaim status before any device manager
//     has run.
//
// The table is therefore the single observable source of truth for "which pod
// holds which device" and is visible via `cilium-dbg statedb dump`.
// ---------------------------------------------------------------------------

const (
	DevicesTableName     = "networkdriver-dra-devices"
	AllocationsTableName = "networkdriver-dra-allocations"
)

// deviceByName is the single primary index, keyed by device name.
var deviceByName = statedb.Index[*DRADevice, string]{
	Name: "id",
	FromObject: func(d *DRADevice) index.KeySet {
		return index.NewKeySet(index.String(d.Name))
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

var allocationByKey = statedb.Index[*DRAAllocation, string]{
	Name: "id",
	FromObject: func(a *DRAAllocation) index.KeySet {
		return index.NewKeySet(index.String(AllocationKey(a.Pool, a.DeviceName)))
	},
	FromKey:    index.String,
	FromString: index.FromString,
	Unique:     true,
}

var allocationByClaimUID = statedb.Index[*DRAAllocation, string]{
	Name: "claim-uid",
	FromObject: func(a *DRAAllocation) index.KeySet {
		return index.NewKeySet(index.String(string(a.ClaimUID)))
	},
	FromKey:    index.String,
	FromString: index.FromString,
	Unique:     false,
}

var allocationByDeviceName = statedb.Index[*DRAAllocation, string]{
	Name: "device-name",
	FromObject: func(a *DRAAllocation) index.KeySet {
		return index.NewKeySet(index.String(a.DeviceName))
	},
	FromKey:    index.String,
	FromString: index.FromString,
	Unique:     false,
}

var allocationByPodUID = statedb.Index[*DRAAllocation, string]{
	Name: "pod-uid",
	FromObject: func(a *DRAAllocation) index.KeySet {
		return index.NewKeySet(index.String(string(a.PodUID)))
	},
	FromKey:    index.String,
	FromString: index.FromString,
	Unique:     false,
}

// DevicesByClaimUID returns all devices allocated for the given claim UID.
func DevicesByClaimUID(tbl statedb.Table[*DRADevice], txn statedb.ReadTxn, claimUID kube_types.UID) iter.Seq2[*DRADevice, statedb.Revision] {
	return tbl.List(txn, deviceByClaimUID.Query(string(claimUID)))
}

// AllocationKey returns the primary key for a device allocation.
func AllocationKey(pool, deviceName string) string {
	return pool + "/" + deviceName
}

// AllocationsByDeviceName returns all allocations for the given device.
func AllocationsByDeviceName(tbl statedb.Table[*DRAAllocation], txn statedb.ReadTxn, deviceName string) iter.Seq2[*DRAAllocation, statedb.Revision] {
	return tbl.List(txn, allocationByDeviceName.Query(deviceName))
}

// AllocationsByClaimUID returns all allocations for the given claim UID.
func AllocationsByClaimUID(tbl statedb.Table[*DRAAllocation], txn statedb.ReadTxn, claimUID kube_types.UID) iter.Seq2[*DRAAllocation, statedb.Revision] {
	return tbl.List(txn, allocationByClaimUID.Query(string(claimUID)))
}

// AllocationsByPodUID returns all allocations for the given pod UID.
func AllocationsByPodUID(tbl statedb.Table[*DRAAllocation], txn statedb.ReadTxn, podUID kube_types.UID) iter.Seq2[*DRAAllocation, statedb.Revision] {
	return tbl.List(txn, allocationByPodUID.Query(string(podUID)))
}

// allocationFromRow projects a statedb row into an allocation. Returns the
// zero allocation and ok=false if the row has no live device handle.
func allocationFromRow(row *DRADevice) (allocation, bool) {
	if row.Dev == nil {
		return allocation{}, false
	}
	return allocation{
		Device:  row.Dev,
		Config:  row.Config,
		Manager: row.Manager,
		Pool:    row.Pool,
	}, true
}

// DRADevice represents a device known to the network driver.
//
// Discovery fields (Name, Manager, Dev) are always present.
//
// Allocation fields (PodUID, ClaimUID, Config) are non-zero when the device
// has been prepared for a pod via PrepareResourceClaims, and are cleared by
// UnprepareResourceClaims. On agent restart they are restored from the
// ResourceClaim status via restoreDevices.
type DRADevice struct {
	// Name is the device name assigned by the device manager.
	// It is the primary key and the name used in ResourceSlice advertisements.
	// It does not necessarily match the kernel interface name.
	Name    string
	Manager types.DeviceManagerType
	Dev     types.Device

	// Allocation fields — non-zero when the device is prepared for a pod.
	Pool     string
	PodUID   kube_types.UID
	ClaimUID kube_types.UID
	Config   types.DeviceConfig
}

func (d *DRADevice) Clone() *DRADevice {
	c := *d
	return &c
}

func (d *DRADevice) TableHeader() []string {
	return []string{"Name", "Manager", "PodUID", "ClaimUID", "PodIfName"}
}

func (d *DRADevice) TableRow() []string {
	return []string{
		d.Name, d.Manager.String(),
		string(d.PodUID), string(d.ClaimUID), d.Config.PodIfName,
	}
}

// DRAAllocation records a device prepared for a ResourceClaim held by a pod.
type DRAAllocation struct {
	DeviceName     string
	Manager        types.DeviceManagerType
	PreparedDevice types.Device
	Pool           string
	PodUID         kube_types.UID
	ClaimUID       kube_types.UID
	Config         types.DeviceConfig
}

func (a *DRAAllocation) Clone() *DRAAllocation {
	c := *a
	return &c
}

func (a *DRAAllocation) TableHeader() []string {
	return []string{"Device", "Manager", "Pool", "PodUID", "ClaimUID", "PodIfName"}
}

func (a *DRAAllocation) TableRow() []string {
	return []string{
		a.DeviceName, a.Manager.String(), a.Pool,
		string(a.PodUID), string(a.ClaimUID), a.Config.PodIfName,
	}
}

func newDeviceTable(db *statedb.DB) (statedb.RWTable[*DRADevice], error) {
	return statedb.NewTable(
		db,
		DevicesTableName,
		deviceByName,
		deviceByClaimUID,
	)
}

func newAllocationTable(db *statedb.DB) (statedb.RWTable[*DRAAllocation], error) {
	return statedb.NewTable(
		db,
		AllocationsTableName,
		allocationByKey,
		allocationByClaimUID,
		allocationByDeviceName,
		allocationByPodUID,
	)
}
