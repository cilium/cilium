// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package linux

import (
	"fmt"
	"log/slog"
	"strings"

	"github.com/cilium/hive/cell"
	"github.com/cilium/statedb"

	"github.com/cilium/cilium/pkg/datapath/tables"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/option"
)

// DeviceManager is a temporary compatibility bridge to keep DeviceManager uses as is and reuse its tests
// against DevicesController and the devices table.
//
// This will be refactored away in follow-up PRs that convert code over to the devices table.
// The DirectRoutingDevice and IPv6MCastDevice would computed from the devices table as necessary.
type DeviceManager struct {
	params         devicesManagerParams
	initialDevices []string
	hive           *hive.Hive
}

func (dm *DeviceManager) Detect(k8sEnabled bool) ([]string, error) {
	rxn := dm.params.DB.ReadTxn()
	devs, _ := tables.SelectedDevices(dm.params.DeviceTable, rxn)
	names := tables.DeviceNames(devs)
	dm.initialDevices = names

	// Look up the device that holds the node IP. Used as fallback for direct-routing
	// and multicast devices.
	var nodeDevice *tables.Device
	if k8sEnabled {
		nodeIP := node.GetK8sNodeIP()
		for _, dev := range devs {
			if dev.HasIP(nodeIP) {
				nodeDevice = dev
				break
			}
		}
	}

	if option.Config.DirectRoutingDeviceRequired() {
		var filter tables.DeviceFilter
		if option.Config.DirectRoutingDevice != "" {
			filter = tables.DeviceFilter(strings.Split(option.Config.DirectRoutingDevice, ","))
		}
		option.Config.DirectRoutingDevice = ""
		if filter.NonEmpty() {
			// User has defined a direct-routing device. Try to find the first matching
			// device.
			for _, dev := range devs {
				if filter.Match(dev.Name) {
					option.Config.DirectRoutingDevice = dev.Name
					break
				}
			}
		} else if len(devs) == 1 {
			option.Config.DirectRoutingDevice = devs[0].Name
		} else if nodeDevice != nil {
			option.Config.DirectRoutingDevice = nodeDevice.Name
		}
		if option.Config.DirectRoutingDevice == "" {
			return nil, fmt.Errorf("unable to determine direct routing device. Use --%s to specify it",
				option.DirectRoutingDevice)
		}
		dm.params.Log.Info("Direct routing device detected",
			logfields.DirectRoutingDevice, option.Config.DirectRoutingDevice,
		)
	}

	return names, nil
}

type devicesManagerParams struct {
	cell.In

	Log         *slog.Logger
	DB          *statedb.DB
	DeviceTable statedb.Table[*tables.Device]
	RouteTable  statedb.Table[*tables.Route]
}

// newDeviceManager constructs a DeviceManager that implements the old DeviceManager API.
// Dummy dependency to *devicesController to make sure devices table is populated.
func newDeviceManager(p devicesManagerParams, _ *devicesController) *DeviceManager {
	return &DeviceManager{params: p, hive: nil}
}
