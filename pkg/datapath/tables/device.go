// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package tables

import (
	"fmt"
	"net"
	"net/netip"

	"github.com/hashicorp/go-memdb"
	"golang.org/x/exp/slices"

	"github.com/cilium/cilium/pkg/statedb"
)

const (
	DeviceNameIndex statedb.Index = "Name"
)

// deviceTableSchema defines the table schema for the device table.
//
// It contains all the network devices on the local node. The
// ones used by Cilium have 'Selected' set to true. We track all
// devices to collect address and route information while the device
// is perhaps not yet selected.
//
// Use the SelectedDevices() query function to look up and watch
// the devices that should be used.
var deviceTableSchema = &memdb.TableSchema{
	Name: "devices",
	Indexes: map[string]*memdb.IndexSchema{
		string(statedb.IDIndex): {
			Name:         string(statedb.IDIndex),
			AllowMissing: false,
			Unique:       true,
			Indexer:      &memdb.IntFieldIndex{Field: "Index"},
		},
		string(DeviceNameIndex): {
			Name: string(DeviceNameIndex),
			// Name can be temporarily missing if we create the device
			// from an address update.
			AllowMissing: true,
			Unique:       true,
			Indexer:      &memdb.StringFieldIndex{Field: "Name"},
		},
	},
}

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

func (d *Device) String() string {
	return fmt.Sprintf("Device{Index:%d, Name:%s, len(Addrs):%d}", d.Index, d.Name, len(d.Addrs))
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
	Addr  netip.Addr
	Scope uint8 // Routing table scope
}

func (d *DeviceAddress) AsIP() net.IP {
	return d.Addr.AsSlice()
}

// DeviceByIndex constructs a query to find a device by its
// interface index.
func DeviceByIndex(index int) statedb.Query {
	return statedb.Query{Index: statedb.IDIndex, Args: []any{index}}
}

// DeviceByName constructs a query to find a device by its
// name.
func DeviceByName(name string) statedb.Query {
	return statedb.Query{Index: DeviceNameIndex, Args: []any{name}}
}

// SelectedDevices returns the network devices selected for
// Cilium use.
//
// The invalidated channel is closed when devices have changed and
// should be requeried with a new transaction.
func SelectedDevices(r statedb.TableReader[*Device]) (devs []*Device, invalidated <-chan struct{}) {
	iter, err := r.Get(statedb.Query{Index: DeviceNameIndex})
	if err != nil {
		// table schema is malformed?
		panic(err)
	}
	for dev, ok := iter.Next(); ok; dev, ok = iter.Next() {
		if !dev.Selected {
			continue
		}
		devs = append(devs, dev)
	}
	return devs, iter.Invalidated()
}

// DeviceNames extracts the device names from a slice of devices.
func DeviceNames(devs []*Device) (names []string) {
	names = make([]string, len(devs))
	for i := range devs {
		names[i] = devs[i].Name
	}
	return
}
