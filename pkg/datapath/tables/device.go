// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package tables

import (
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strings"

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
)

func NewDeviceTable() (statedb.RWTable[*Device], error) {
	return statedb.NewTable[*Device](
		"devices",
		DeviceIDIndex,
		DeviceNameIndex,
		DeviceSelectedIndex,
	)
}

// HardwareAddr is the physical address for a network device.
// Defined here instead of using net.Hardwareaddr for proper
// JSON marshalling.
type HardwareAddr []byte

func (a HardwareAddr) String() string {
	return net.HardwareAddr([]byte(a)).String()
}

func (a HardwareAddr) MarshalJSON() ([]byte, error) {
	return []byte("\"" + a.String() + "\""), nil
}

// Device is a local network device along with addresses associated with it.
//
// The devices that are selected are the external facing native devices that
// Cilium will use with features such as load-balancing, host firewall and routing.
// For the selection logic applied see 'pkg/datapath/linux/devices_controller.go'.
type Device struct {
	Index        int             // positive integer that starts at one, zero is never used
	MTU          int             // maximum transmission unit
	Name         string          // e.g., "en0", "lo0", "eth0.100"
	HardwareAddr HardwareAddr    // IEEE MAC-48, EUI-48 and EUI-64 form
	Flags        net.Flags       // e.g. net.FlagUp, net.eFlagLoopback, net.FlagMulticast
	Addrs        []DeviceAddress // Addresses assigned to the device
	RawFlags     uint32          // Raw interface flags
	Type         string          // Device type, e.g. "veth" etc.
	MasterIndex  int             // Index of the master device (e.g. bridge or bonding device)

	Selected          bool   // True if this is an external facing device
	NotSelectedReason string // Reason why this device was not selected
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

func (*Device) TableHeader() []string {
	return []string{
		"Name",
		"Index",
		"Selected",
		"Type",
		"MTU",
		"HWAddr",
		"Flags",
		"Addresses",
	}
}

func (d *Device) TableRow() []string {
	addrs := []string{}
	for _, addr := range d.Addrs {
		addrs = append(addrs, addr.Addr.String())
	}
	return []string{
		d.Name,
		fmt.Sprintf("%d", d.Index),
		fmt.Sprintf("%v", d.Selected),
		d.Type,
		fmt.Sprintf("%d", d.MTU),
		d.HardwareAddr.String(),
		d.Flags.String(),
		strings.Join(addrs, ", "),
	}
}

type DeviceAddress struct {
	Addr      netip.Addr
	Secondary bool
	Scope     uint8 // Address scope, e.g. unix.RT_SCOPE_LINK, unix.RT_SCOPE_HOST etc.
}

func (d *DeviceAddress) AsIP() net.IP {
	return d.Addr.AsSlice()
}

// SelectedDevices returns the external facing network devices to use for
// load-balancing, host firewall and routing.
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
