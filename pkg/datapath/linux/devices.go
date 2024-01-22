// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package linux

import (
	"context"
	"fmt"
	"net"

	"github.com/cilium/cilium/pkg/datapath/tables"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/statedb"
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

	if option.Config.EnableIPv6NDP && option.Config.IPv6MCastDevice == "" {
		if nodeDevice != nil && nodeDevice.Flags&net.FlagMulticast != 0 {
			option.Config.IPv6MCastDevice = nodeDevice.Name
		} else {
			return nil, fmt.Errorf("unable to determine Multicast device. Use --%s to specify it",
				option.IPv6MCastDevice)
		}
	}

	return names, nil
}

type devicesManagerParams struct {
	cell.In

	DB          *statedb.DB
	DeviceTable statedb.Table[*tables.Device]
	RouteTable  statedb.Table[*tables.Route]
}

// newDeviceManager constructs a DeviceManager that implements the old DeviceManager API.
// Dummy dependency to *devicesController to make sure devices table is populated.
func newDeviceManager(p devicesManagerParams, _ *devicesController) *DeviceManager {
	return &DeviceManager{params: p, hive: nil}
}

func (dm *DeviceManager) Stop() {
	if dm.hive != nil {
		dm.hive.Stop(context.TODO())
	}
}
