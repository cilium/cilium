package types

import (
	"context"

	"github.com/cilium/cilium/pkg/datapath/tables"
)

type Devicer interface {
	Devices() ([]string, <-chan struct{})
	DirectRoutingDevice() (*tables.Device, error, <-chan struct{})
	IPv6MCastDevice() (string, error, <-chan struct{})
	K8sNodeDevice() (*tables.Device, <-chan struct{})
	Listen(ctx context.Context) (chan []string, error)
}

type NopDevicer struct {
}

// Devices implements Devicer.
func (NopDevicer) Devices() ([]string, <-chan struct{}) {
	return nil, nil
}

// DirectRoutingDevice implements Devicer.
func (NopDevicer) DirectRoutingDevice() (*tables.Device, error, <-chan struct{}) {
	return nil, nil, nil
}

// IPv6MCastDevice implements Devicer.
func (NopDevicer) IPv6MCastDevice() (string, error, <-chan struct{}) {
	return "", nil, nil
}

// K8sNodeDevice implements Devicer.
func (NopDevicer) K8sNodeDevice() (*tables.Device, <-chan struct{}) {
	return nil, nil
}

// Listen implements Devicer.
func (NopDevicer) Listen(ctx context.Context) (chan []string, error) {
	return nil, nil
}

var _ Devicer = NopDevicer{}
