// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package tables

import (
	"context"

	"github.com/spf13/pflag"

	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/statedb"
)

var DirectRoutingDeviceCell = cell.Module(
	"direct-routing-device",
	"Resolves user configuration to interface used for direct routing",

	cell.Provide(newDirectRoutingDevice),
	cell.Config(DirectRoutingDeviceConfig{}),
)

func (c DirectRoutingDeviceConfig) Flags(flags *pflag.FlagSet) {
	flags.String(option.DirectRoutingDevice, "", "Device name used to connect nodes in direct routing mode (used by BPF NodePort, BPF host routing; if empty, automatically set to a device with k8s InternalIP/ExternalIP or with a default route)")
}

type DirectRoutingDeviceConfig struct {
	DirectRoutingDevice string
}

type DirectRoutingDeviceParams struct {
	cell.In

	Config  DirectRoutingDeviceConfig
	Node    *node.LocalNodeStore `optional:"true"`
	DB      *statedb.DB
	Devices statedb.Table[*Device]
}

type DirectRoutingDevice interface {
	Get(statedb.ReadTxn, context.Context) (*Device, <-chan struct{})
}

type directRoutingDevice struct {
	p *DirectRoutingDeviceParams
}

func newDirectRoutingDevice(p DirectRoutingDeviceParams) DirectRoutingDevice {
	return &directRoutingDevice{
		p: &p,
	}
}

// Get returns the direct routing device and a channel which closes if the
// query invalidates. Can return a nil device, if no suitable device is found.
func (dr *directRoutingDevice) Get(rxn statedb.ReadTxn, ctx context.Context) (*Device, <-chan struct{}) {
	var filter DeviceFilter
	if dr.p.Config.DirectRoutingDevice != "" {
		filter = DeviceFilter([]string{dr.p.Config.DirectRoutingDevice})
	}
	device, watch := PickDirectRoutingDevice(dr.p.Devices, rxn, filter)

	// Fallback to the device matching the K8s Node IP.
	if device == nil && dr.p.Node != nil {
		devs, _ := SelectedDevices(dr.p.Devices, rxn)
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
