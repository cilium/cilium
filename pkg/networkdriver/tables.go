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

const (
	DevicesTableName     = "networkdriver-dra-devices"
	AllocationsTableName = "networkdriver-dra-allocations"
)

var deviceByName = statedb.Index[*DRADevice, string]{
	Name: "id",
	FromObject: func(d *DRADevice) index.KeySet {
		return index.NewKeySet(index.String(d.Name))
	},
	FromKey:    index.String,
	FromString: index.FromString,
	Unique:     true,
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

// DRADevice is a device currently reported by a device manager.
type DRADevice struct {
	// Name is assigned by the device manager and is used in ResourceSlices.
	// It does not necessarily match the kernel interface name.
	Name    string
	Manager types.DeviceManagerType
	Dev     types.Device
}

func (d *DRADevice) Clone() *DRADevice {
	c := *d
	return &c
}

func (d *DRADevice) TableHeader() []string {
	return []string{"Name", "Manager"}
}

func (d *DRADevice) TableRow() []string {
	return []string{d.Name, d.Manager.String()}
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
