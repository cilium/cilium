package types

import (
	"context"

	"github.com/cilium/cilium/pkg/datapath/tables"
)

type Devices interface {
	NativeDeviceNames() ([]string, <-chan struct{})
	NativeDevices() ([]*tables.Device, <-chan struct{})
	GetDevice(string) *tables.Device
	DirectRoutingDevice() (*tables.Device, error, <-chan struct{})
	IPv6MCastDevice() (string, error, <-chan struct{})
	K8sNodeDevice() (*tables.Device, <-chan struct{})
	Listen(ctx context.Context) (chan []string, error)
}

type FakeDevices struct {
	Devices []*tables.Device
}

// NativeDeviceNames implements Devices.
func (f *FakeDevices) NativeDeviceNames() ([]string, <-chan struct{}) {
	return tables.DeviceNames(f.Devices), nil
}

// NativeDevices implements Devices.
func (f *FakeDevices) NativeDevices() ([]*tables.Device, <-chan struct{}) {
	return f.Devices, nil
}

func (f *FakeDevices) GetDevice(name string) *tables.Device {
	for _, dev := range f.Devices {
		if dev.Name == name {
			return dev
		}
	}
	return nil
}

// DirectRoutingDevice implements Devices.
func (*FakeDevices) DirectRoutingDevice() (*tables.Device, error, <-chan struct{}) {
	return nil, nil, nil
}

// IPv6MCastDevice implements Devices.
func (*FakeDevices) IPv6MCastDevice() (string, error, <-chan struct{}) {
	return "", nil, nil
}

// K8sNodeDevice implements Devices.
func (*FakeDevices) K8sNodeDevice() (*tables.Device, <-chan struct{}) {
	return nil, nil
}

// Listen implements Devices.
func (*FakeDevices) Listen(ctx context.Context) (chan []string, error) {
	return nil, nil
}

var _ Devices = &FakeDevices{}
