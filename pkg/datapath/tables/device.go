// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package tables

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"strings"

	"golang.org/x/exp/slices"

	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/option"
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
	Addrs       []DeviceAddress // Addresses assigned to the device. Sorted by scope.
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

func (d *Device) IPv4() *DeviceAddress {
	for _, addr := range d.Addrs {
		if addr.Is4() {
			return &addr
		}
	}
	return nil
}

func (d *Device) IPv6() *DeviceAddress {
	for _, addr := range d.Addrs {
		if addr.Is6() {
			return &addr
		}
	}
	return nil
}

type DeviceAddress struct {
	netip.Addr
	Flags int
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

func DirectRoutingDevice(tbl statedb.Table[*Device], txn statedb.ReadTxn) (*Device, <-chan struct{}, error) {
	devs, watch := SelectedDevices(tbl, txn)
	dev, err := PickDirectRoutingDevice(devs)
	return dev, watch, err
}

func PickDirectRoutingDevice(devs []*Device) (*Device, error) {
	var (
		filter              deviceFilter
		directRoutingDevice *Device
	)

	if option.Config.DirectRoutingDevice != "" {
		filter = deviceFilter(strings.Split(option.Config.DirectRoutingDevice, ","))
	}

	for _, dev := range devs {
		if filter.match(dev.Name) {
			directRoutingDevice = dev
			break
		}
	}

	if directRoutingDevice == nil {
		return nil, fmt.Errorf("unable to determine direct routing device. Use --%s to specify it",
			option.DirectRoutingDevice)
	}
	return directRoutingDevice, nil
}

func IPv6MCastDevice(localNode *node.LocalNodeStore, devs []*Device) (*Device, error) {
	nodeDevice := K8sNodeDevice(localNode, devs)

	if nodeDevice != nil && nodeDevice.Flags&net.FlagMulticast != 0 {
		return nodeDevice, nil
	}
	return nil, fmt.Errorf("unable to determine Multicast device. Use --%s to specify it",
		option.IPv6MCastDevice)
}

func K8sNodeDevice(localNode *node.LocalNodeStore, devs []*Device) *Device {
	node, _ := localNode.Get(context.TODO())
	nodeIP := node.GetK8sNodeIP()
	for _, dev := range devs {
		if dev.HasIP(nodeIP) {
			return dev
		}
	}
	return nil
}

// deviceFilter implements filtering device names either by
// concrete name ("eth0") or by iptables-like wildcard ("eth+").
type deviceFilter []string

// nonEmpty returns true if the filter has been defined
// (i.e. user has specified --devices).
func (lst deviceFilter) nonEmpty() bool {
	return len(lst) > 0
}

// match checks whether the given device name passes the filter
func (lst deviceFilter) match(dev string) bool {
	if len(lst) == 0 {
		return true
	}
	for _, entry := range lst {
		if strings.HasSuffix(entry, "+") {
			prefix := strings.TrimRight(entry, "+")
			if strings.HasPrefix(dev, prefix) {
				return true
			}
		} else if dev == entry {
			return true
		}
	}
	return false
}
