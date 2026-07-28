// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package networkdriver

import (
	"github.com/cilium/statedb"
	"github.com/cilium/statedb/index"
	"github.com/cilium/statedb/reconciler"
	resourceapi "k8s.io/api/resource/v1"
	kube_types "k8s.io/apimachinery/pkg/types"

	"github.com/cilium/cilium/pkg/networkdriver/types"
)

// ---------------------------------------------------------------------------
// Device — single table tracking every device known to the driver.
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

const DevicesTableName = "networkdriver-devices"

const (
	deviceIndexName    = "id"
	deviceIndexPool    = "pool"
	deviceIndexManager = "manager"
	deviceIndexPodUID  = "pod"
	deviceIndexClaim   = "claim"
)

const (
	deviceColName      = "Name"
	deviceColManager   = "Manager"
	deviceColPool      = "Pool"
	deviceColPodUID    = "PodUID"
	deviceColClaimUID  = "ClaimUID"
	deviceColPodIfName = "PodIfName"
	deviceColStatus    = "Status"
)

// Device represents a device known to the network driver.
// Allocation fields (PodUID, ClaimUID, Config) are zero when the device is
// unallocated; non-zero when prepared for a pod.
type Device struct {
	// Name is the device name assigned by the device manager (Device.IfName()).
	// It is the primary key and the name used in ResourceSlice advertisements.
	// It does not necessarily match the kernel interface name (Device.KernelIfName()).
	Name    string
	Manager types.DeviceManagerType
	Dev     types.Device
	Pool    string // resolved pool name (empty if unmatched)
	Attrs   map[resourceapi.QualifiedName]resourceapi.DeviceAttribute

	// Allocation state — zero values mean the device is free.
	PodUID   kube_types.UID
	ClaimUID kube_types.UID
	Config   types.DeviceConfig // {PodIfName, Vlan, ...}

	Status reconciler.Status
}

// IsAllocated reports whether the device has been prepared for a pod.
func (d *Device) IsAllocated() bool { return d.PodUID != "" }

func (d *Device) GetStatus() reconciler.Status { return d.Status }
func (d *Device) SetStatus(s reconciler.Status) *Device {
	d.Status = s
	return d
}
func (d *Device) Clone() *Device {
	c := *d
	return &c
}

func (d *Device) TableHeader() []string {
	return []string{
		deviceColName, deviceColManager, deviceColPool,
		deviceColPodUID, deviceColClaimUID, deviceColPodIfName, deviceColStatus,
	}
}
func (d *Device) TableRow() []string {
	return []string{
		d.Name, d.Manager.String(), d.Pool,
		string(d.PodUID), string(d.ClaimUID), d.Config.PodIfName, d.Status.String(),
	}
}

var (
	DeviceByName     = deviceNameIndex.Query
	DeviceByPool     = devicePoolIndex.Query
	DeviceByManager  = deviceManagerIndex.Query
	DeviceByPodUID   = devicePodUIDIndex.Query
	DeviceByClaimUID = deviceClaimIndex.Query

	// deviceNameIndex is the primary (unique) index keyed by device ifname.
	deviceNameIndex = statedb.Index[*Device, string]{
		Name: deviceIndexName,
		FromObject: func(d *Device) index.KeySet {
			return index.NewKeySet(index.String(d.Name))
		},
		FromKey:    index.String,
		FromString: index.FromString,
		Unique:     true,
	}

	// devicePoolIndex is a secondary (non-unique) index on the resolved pool name.
	devicePoolIndex = statedb.Index[*Device, string]{
		Name: deviceIndexPool,
		FromObject: func(d *Device) index.KeySet {
			return index.NewKeySet(index.String(d.Pool))
		},
		FromKey:    index.String,
		FromString: index.FromString,
	}

	// deviceManagerIndex is a secondary (non-unique) index on the DeviceManagerType.
	deviceManagerIndex = statedb.Index[*Device, types.DeviceManagerType]{
		Name: deviceIndexManager,
		FromObject: func(d *Device) index.KeySet {
			return index.NewKeySet(index.String(d.Manager.String()))
		},
		FromKey: func(m types.DeviceManagerType) index.Key {
			return index.String(m.String())
		},
		FromString: func(s string) (index.Key, error) {
			return index.String(s), nil
		},
	}

	// devicePodUIDIndex is a secondary (non-unique) index on PodUID.
	// An empty PodUID means the device is unallocated; querying with "" returns
	// all free devices.
	devicePodUIDIndex = statedb.Index[*Device, kube_types.UID]{
		Name: deviceIndexPodUID,
		FromObject: func(d *Device) index.KeySet {
			return index.NewKeySet(index.String(string(d.PodUID)))
		},
		FromKey: func(uid kube_types.UID) index.Key {
			return index.String(string(uid))
		},
		FromString: func(s string) (index.Key, error) {
			return index.String(s), nil
		},
	}

	// deviceClaimIndex is a secondary (non-unique) index on ClaimUID,
	// allowing efficient lookup of all devices allocated for a single claim.
	deviceClaimIndex = statedb.Index[*Device, kube_types.UID]{
		Name: deviceIndexClaim,
		FromObject: func(d *Device) index.KeySet {
			return index.NewKeySet(index.String(string(d.ClaimUID)))
		},
		FromKey: func(uid kube_types.UID) index.Key {
			return index.String(string(uid))
		},
		FromString: func(s string) (index.Key, error) {
			return index.String(s), nil
		},
	}
)

func NewDeviceTable(db *statedb.DB) (statedb.RWTable[*Device], error) {
	return statedb.NewTable(
		db,
		DevicesTableName,
		deviceNameIndex,
		devicePoolIndex,
		deviceManagerIndex,
		devicePodUIDIndex,
		deviceClaimIndex,
	)
}
