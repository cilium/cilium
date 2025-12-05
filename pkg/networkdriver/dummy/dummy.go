// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package dummy

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"slices"
	"strings"

	resourceapi "k8s.io/api/resource/v1"
	"k8s.io/utils/ptr"

	"github.com/cilium/cilium/pkg/datapath/linux/safenetlink"
	"github.com/cilium/cilium/pkg/networkdriver/types"
)

type DummyConfig struct {
	Enabled bool
}

func (cfg DummyConfig) IsEnabled() bool {
	return cfg.Enabled
}

type DummyManager struct {
	logger *slog.Logger
	config DummyConfig
}

func (m *DummyManager) init() error {
	return nil
}

func NewManager(logger *slog.Logger, cfg DummyConfig) (*DummyManager, error) {
	mgr := &DummyManager{
		logger: logger,
		config: cfg,
	}

	return mgr, mgr.init()
}

func (mgr *DummyManager) ListDevices() ([]types.Device, error) {
	links, err := safenetlink.LinkList()
	if err != nil {
		return nil, fmt.Errorf("failed to get links: %w", err)
	}

	var (
		devices []types.Device
		errs    []error
	)

	for _, link := range links {
		if link.Type() != "dummy" {
			continue
		}

		// Skip down interfaces
		if link.Attrs().Flags&net.FlagUp == 0 {
			continue
		}

		devices = append(devices, DummyDevice{
			name:   link.Attrs().Name,
			hwAddr: link.Attrs().HardwareAddr.String(),
			mtu:    link.Attrs().MTU,
			flags:  link.Attrs().Flags.String(),
		})
	}

	return devices, errors.Join(errs...)
}

type DummyDevice struct {
	name   string
	hwAddr string
	mtu    int
	flags  string
}

func (d DummyDevice) GetAttrs() map[resourceapi.QualifiedName]resourceapi.DeviceAttribute {
	result := make(map[resourceapi.QualifiedName]resourceapi.DeviceAttribute)
	result["interface_name"] = resourceapi.DeviceAttribute{StringValue: ptr.To(d.IfName())}
	result["mac_address"] = resourceapi.DeviceAttribute{StringValue: ptr.To(d.hwAddr)}
	result["mtu"] = resourceapi.DeviceAttribute{IntValue: ptr.To(int64(d.mtu))}
	result["flags"] = resourceapi.DeviceAttribute{StringValue: ptr.To(d.flags)}

	return result
}

func (d DummyDevice) Setup(cfg types.DeviceConfig) error {
	return nil
}

func (d DummyDevice) Free(cfg types.DeviceConfig) error {
	return nil
}

func (d DummyDevice) Match(filter types.DeviceFilter) bool {
	if len(filter.DriverTypes) != 0 && !slices.Contains(filter.DriverTypes, types.DeviceManagerTypeDummy) {
		return false
	}
	for _, ifname := range filter.IfNames {
		if !strings.HasPrefix(d.IfName(), ifname) {
			return false
		}
	}
	return true
}

func (d DummyDevice) IfName() string {
	return d.name
}

func (d DummyDevice) KernelIfName() string {
	return d.name
}
