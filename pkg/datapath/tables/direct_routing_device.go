// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package tables

import (
	"context"

	"github.com/cilium/hive/cell"
	"github.com/cilium/statedb"
	"github.com/sirupsen/logrus"
	"github.com/spf13/pflag"

	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/option"
)

var DirectRoutingDeviceCell = cell.Module(
	"direct-routing-device",
	"Resolves user configuration to interface used for direct routing",

	cell.Provide(NewDirectRoutingDevice),
	cell.Config(DirectRoutingDeviceConfig{}),
)

func (c DirectRoutingDeviceConfig) Flags(flags *pflag.FlagSet) {
	flags.String(
		option.DirectRoutingDevice,
		"",
		"Device name used to connect nodes in direct routing mode (used by BPF NodePort, "+
			"BPF host routing; if empty, automatically set to a device with k8s "+
			"InternalIP/ExternalIP or with a default route)",
	)
}

type DirectRoutingDeviceConfig struct {
	DirectRoutingDevice string
}

type DirectRoutingDeviceParams struct {
	cell.In

	Log     logrus.FieldLogger
	Config  DirectRoutingDeviceConfig
	Node    *node.LocalNodeStore `optional:"true"`
	DB      *statedb.DB
	Devices statedb.Table[*Device]
}

type DirectRoutingDevice struct {
	p *DirectRoutingDeviceParams
}

func NewDirectRoutingDevice(p DirectRoutingDeviceParams) DirectRoutingDevice {
	return DirectRoutingDevice{&p}
}

// Get returns the direct routing device and a channel which closes if the
// query invalidates. Can return a nil device, if no suitable device is found.
func (dr DirectRoutingDevice) Get(ctx context.Context, rxn statedb.ReadTxn) (*Device, <-chan struct{}) {
	var filter DeviceFilter
	if dr.p.Config.DirectRoutingDevice != "" {
		filter = DeviceFilter([]string{dr.p.Config.DirectRoutingDevice})
	}

	var device *Device
	devs, watch := SelectedDevices(dr.p.Devices, rxn)
	if filter.NonEmpty() {
		// User has defined a direct-routing device. Try to find the first matching
		// device.
		for _, dev := range devs {
			if filter.Match(dev.Name) {
				device = dev
				break
			}
		}
	} else if len(devs) == 1 {
		device = devs[0]
	}

	// Fallback to the device matching the K8s Node IP.
	if device == nil && dr.p.Node != nil {
		node, err := dr.p.Node.Get(ctx)
		if err == nil {
			nodeIP := node.GetK8sNodeIP()
			for _, dev := range devs {
				if dev.HasIP(nodeIP) {
					device = dev
					break
				}
			}
		}
	}
	return device, watch
}
