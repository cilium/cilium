// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package tables

import (
	"net"
	"net/netip"

	"golang.org/x/exp/slices"

	"github.com/cilium/cilium/pkg/statedb"
	"github.com/cilium/cilium/pkg/statedb/index"
)

var (
	DeviceIDIndex = statedb.Index[*Device, int]{
		Name: "id",
		FromObject: func(d *Device) index.KeySet {
			return index.NewKeySet(index.Int(d.Index))
		},
		FromKey: func(idx int) []byte {
			return index.Int(idx)
		},
		Unique: true,
	}

	DeviceNameIndex = statedb.Index[*Device, string]{
		Name: "name",
		FromObject: func(d *Device) index.KeySet {
			return index.NewKeySet(index.String(d.Name))
		},
		FromKey: func(name string) []byte {
			return index.String(name)
		},
	}

	DeviceSelectedIndex = statedb.Index[*Device, bool]{
		Name: "selected",
		FromObject: func(d *Device) index.KeySet {
			return index.NewKeySet(index.Bool(d.Selected))
		},
		FromKey: func(selected bool) []byte {
			return index.Bool(selected)
		},
	}

	DeviceTableCell = statedb.NewTableCell[*Device](
		"devices",
		DeviceIDIndex,
		DeviceNameIndex,
		DeviceSelectedIndex,
	)
)

// Device is a local network device along with addresses associated with it.
type Device struct {
	Index        int              // positive integer that starts at one, zero is never used
	MTU          int              // maximum transmission unit
	Name         string           // e.g., "en0", "lo0", "eth0.100"
	HardwareAddr net.HardwareAddr // IEEE MAC-48, EUI-48 and EUI-64 form
	Flags        net.Flags        // e.g. net.FlagUp, net.eFlagLoopback, net.FlagMulticast

	Selected    bool            // If true this device can be used by Cilium
	Addrs       []DeviceAddress // Addresses assigned to the device
	RawFlags    uint32          // Raw interface flags
	Type        string          // Device type, e.g. "veth" etc.
	MasterIndex int             // Index of the master device (e.g. bridge or bonding device)
}

func (d *Device) DeepCopy() *Device {
	copy := *d
	copy.Addrs = slices.Clone(d.Addrs)
	return &copy
}

func (d *Device) HasIP(ip net.IP) bool {
	for _, addr := range d.Addrs {
		if addr.AsIP().Equal(ip) {
			return true
		}
	}
	return false
}

type DeviceAddress struct {
	netip.Addr
	Scope uint8 // Address scope
}

func (d *DeviceAddress) AsIP() net.IP {
	return d.Addr.AsSlice()
}

// SelectedDevices returns the network devices selected for
// Cilium use.
//
// The invalidated channel is closed when devices have changed and
// should be requeried with a new transaction.
func SelectedDevices(tbl statedb.Table[*Device], txn statedb.ReadTxn) ([]*Device, <-chan struct{}) {
	iter, invalidated := tbl.Get(txn, DeviceSelectedIndex.Query(true))
	return statedb.Collect(iter), invalidated
}

// DeviceNames extracts the device names from a slice of devices.
func DeviceNames(devs []*Device) (names []string) {
	names = make([]string, len(devs))
	for i := range devs {
		names[i] = devs[i].Name
	}
	return
}
