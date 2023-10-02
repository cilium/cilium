package datapath

import (
	"context"
	"fmt"
	"net"
	"strings"

	"github.com/cilium/cilium/pkg/datapath/tables"
	"github.com/cilium/cilium/pkg/datapath/types"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/statedb"
	"golang.org/x/exp/slices"
)

func newDevicesAccessor(
	db *statedb.DB,
	devices statedb.Table[*tables.Device],
	localNode *node.LocalNodeStore,
) types.Devices {
	return &DevicesAccessor{db, devices, localNode}
}

type DevicesAccessor struct {
	db        *statedb.DB
	devices   statedb.Table[*tables.Device]
	localNode *node.LocalNodeStore
}

func (d *DevicesAccessor) NativeDeviceNames() ([]string, <-chan struct{}) {
	devs, watch := d.NativeDevices()
	return tables.DeviceNames(devs), watch
}

func (d *DevicesAccessor) NativeDevices() ([]*tables.Device, <-chan struct{}) {
	return tables.SelectedDevices(d.devices, d.db.ReadTxn())
}

func (d *DevicesAccessor) GetDevice(name string) *tables.Device {
	dev, _, _ := d.devices.First(d.db.ReadTxn(), tables.DeviceNameIndex.Query(name))
	return dev
}

func (d *DevicesAccessor) DirectRoutingDevice() (*tables.Device, error, <-chan struct{}) {
	devs, watch := tables.SelectedDevices(d.devices, d.db.ReadTxn())

	var (
		filter              deviceFilter
		directRoutingDevice *tables.Device
	)

	if option.Config.DirectRoutingDevice != "" { // TODO: Move device-related options out from option.Config
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
			option.DirectRoutingDevice), watch
	}
	return directRoutingDevice, nil, watch
}

func (d *DevicesAccessor) IPv6MCastDevice() (string, error, <-chan struct{}) {
	nodeDevice, watch := d.K8sNodeDevice()

	if nodeDevice != nil && nodeDevice.Flags&net.FlagMulticast != 0 {
		return nodeDevice.Name, nil, watch
	}
	return "", fmt.Errorf("unable to determine Multicast device. Use --%s to specify it",
		option.IPv6MCastDevice), watch
}

func (d *DevicesAccessor) K8sNodeDevice() (*tables.Device, <-chan struct{}) {
	devs, watch := tables.SelectedDevices(d.devices, d.db.ReadTxn())

	// Look up the device that holds the node IP. Used as fallback for direct-routing
	// and multicast devices.
	var nodeDevice *tables.Device
	node, _ := d.localNode.Get(context.TODO())
	nodeIP := node.GetK8sNodeIP()
	for _, dev := range devs {
		if dev.HasIP(nodeIP) {
			nodeDevice = dev
			break
		}
	}
	return nodeDevice, watch
}

func (d *DevicesAccessor) Listen(ctx context.Context) (chan []string, error) {
	devs := make(chan []string)

	go func() {
		defer close(devs)

		devStructs, _ := tables.SelectedDevices(d.devices, d.db.ReadTxn())
		prevDevices := tables.DeviceNames(devStructs)

		for {
			rxn := d.db.ReadTxn()
			devices, watch := tables.SelectedDevices(d.devices, rxn)
			newDevices := tables.DeviceNames(devices)

			if slices.Equal(prevDevices, newDevices) {
				continue
			}
			select {
			case devs <- newDevices:
			case <-ctx.Done():
				return
			}
			select {
			case <-watch:
			case <-ctx.Done():
				return
			}
			prevDevices = newDevices
		}
	}()
	return devs, nil
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
