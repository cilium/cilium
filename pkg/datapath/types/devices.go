package types

import (
	"context"

	"github.com/cilium/cilium/pkg/datapath/tables"
)

type Devicer interface {
	NativeDeviceNames() ([]string, <-chan struct{})
	NativeDevices() ([]*tables.Device, <-chan struct{})
	GetDevice(string) *tables.Device
	DirectRoutingDevice() (*tables.Device, error, <-chan struct{})
	IPv6MCastDevice() (string, error, <-chan struct{})
	K8sNodeDevice() (*tables.Device, <-chan struct{})
	Listen(ctx context.Context) (chan []string, error)
}

type FakeDevicer struct {
	Devices []*tables.Device
}

// NativeDeviceNames implements Devicer.
func (f *FakeDevicer) NativeDeviceNames() ([]string, <-chan struct{}) {
	return tables.DeviceNames(f.Devices), nil
}

// NativeDevices implements Devicer.
func (f *FakeDevicer) NativeDevices() ([]*tables.Device, <-chan struct{}) {
	return f.Devices, nil
}

func (f *FakeDevicer) GetDevice(name string) *tables.Device {
	for _, dev := range f.Devices {
		if dev.Name == name {
			return dev
		}
	}
	return nil
}

// DirectRoutingDevice implements Devicer.
func (*FakeDevicer) DirectRoutingDevice() (*tables.Device, error, <-chan struct{}) {
	return nil, nil, nil
}

// IPv6MCastDevice implements Devicer.
func (*FakeDevicer) IPv6MCastDevice() (string, error, <-chan struct{}) {
	return "", nil, nil
}

// K8sNodeDevice implements Devicer.
func (*FakeDevicer) K8sNodeDevice() (*tables.Device, <-chan struct{}) {
	return nil, nil
}

// Listen implements Devicer.
func (*FakeDevicer) Listen(ctx context.Context) (chan []string, error) {
	return nil, nil
}

var _ Devicer = &FakeDevicer{}
