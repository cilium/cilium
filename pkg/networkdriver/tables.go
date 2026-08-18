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

const DevicesTableName = "networkdriver-dra-devices"

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

// DevicesByClaimUID returns all devices allocated for the given claim UID.
func DevicesByClaimUID(tbl statedb.Table[*DRADevice], txn statedb.ReadTxn, claimUID kube_types.UID) iter.Seq2[*DRADevice, statedb.Revision] {
	return tbl.List(txn, deviceByClaimUID.Query(string(claimUID)))
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

func newDeviceTable(db *statedb.DB) (statedb.RWTable[*DRADevice], error) {
	return statedb.NewTable(
		db,
		DevicesTableName,
		deviceByName,
		deviceByClaimUID,
	)
}
