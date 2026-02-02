// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package types

import (
	"encoding"
	"encoding/json"
	"errors"
	"net/netip"
	"strings"

	resourceapi "k8s.io/api/resource/v1"

	"github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
)

// The labels below are used by the device managers
// to tag their devices for advertising ResourceSlices.
// These attributes may be used to filter and match
// devices on a resource claim.
const (
	// KernelIfNameLabel contains the interface name
	// assigned by the kernel.
	KernelIfNameLabel = "kernelIfName"
	// IfNameLabel contains the name of the device
	// as assigned by the device managers.
	// must be unique across all devices on the node.
	IfNameLabel = "ifName"
	// PCIAddrLabel contains the PCI address for
	// the device. Only applicable to PCI based devices.
	PCIAddrLabel = "pciAddr"
	// PFNameLabel contains the kernel ifname for the
	// PF on a VF device. Only applicable to sr-iov
	// VF devices.
	PFNameLabel = "pfName"
	// VendorLabel identifies the vendor of this device
	// same as /sys/bus/pci/devices/<pciAddr>/vendor
	VendorLabel = "vendor"
	// DeviceIDLabel contains a device's device id
	// same as /sys/bus/pci/devices/<pciAddr>/device
	DeviceIDLabel = "deviceID"
	// DriverLabel identifies a device's driver.
	DriverLabel = "driver"
	// HWAddrLabel contains the MAC address of the device.
	HWAddrLabel = "mac_address"
	// MTULabel contains the MTU value set for the device.
	MTULabel = "mtu"
	// FlagsLabel contains the flags set for the device.
	FlagsLabel = "flags"
	// DeviceManagerLabel identifies which Device Manager
	// published the device.
	DeviceManagerLabel = "deviceManager"
	// PoolNameLabel is the pool name.
	PoolNameLabel = "pool"
)

var (
	errUnknownDeviceManagerType = errors.New("unknown device manager type")
)

type DeviceManagerType int

const (
	sriovDeviceManagerStr = "sr-iov"
	dummyDeviceManagerStr = "dummy"
)

const (
	DeviceManagerTypeSRIOV DeviceManagerType = iota
	DeviceManagerTypeDummy

	DeviceManagerTypeUnknown
)

func (d DeviceManagerType) String() string {
	switch d {
	case DeviceManagerTypeSRIOV:
		return sriovDeviceManagerStr
	case DeviceManagerTypeDummy:
		return dummyDeviceManagerStr
	}

	return ""
}

func (d DeviceManagerType) MarshalText() (text []byte, err error) {
	switch d {
	case DeviceManagerTypeSRIOV:
		return json.Marshal(sriovDeviceManagerStr)
	case DeviceManagerTypeDummy:
		return json.Marshal(dummyDeviceManagerStr)
	}

	return nil, errUnknownDeviceManagerType
}

func (d *DeviceManagerType) UnmarshalText(text []byte) error {
	var s string
	err := json.Unmarshal(text, &s)
	if err != nil {
		return err
	}

	switch strings.ToLower(s) {
	case sriovDeviceManagerStr:
		*d = DeviceManagerTypeSRIOV
	case dummyDeviceManagerStr:
		*d = DeviceManagerTypeDummy
	default:
		return errUnknownDeviceManagerType
	}

	return nil
}

type Device interface {
	encoding.BinaryMarshaler
	encoding.BinaryUnmarshaler

	GetAttrs() map[resourceapi.QualifiedName]resourceapi.DeviceAttribute
	Setup(cfg DeviceConfig) error
	Free(cfg DeviceConfig) error
	Match(filter v2alpha1.CiliumNetworkDriverDeviceFilter) bool
	IfName() string
	KernelIfName() string
}

type DeviceManager interface {
	Type() DeviceManagerType
	ListDevices() ([]Device, error)
	RestoreDevice([]byte) (Device, error)
}

type DeviceManagerConfig interface {
	IsEnabled() bool
}

type RouteSet map[netip.Prefix]AddrSet

type AddrSet map[netip.Prefix]struct{}

type DeviceConfig struct {
	IPv4Addr netip.Prefix `json:"ipv4Addr"`
	IPv6Addr netip.Prefix `json:"ipv6Addr"`
	IPPool   string       `json:"ip-pool"`
	Routes   RouteSet
	Vlan     uint16
}

func (d *DeviceConfig) Empty() bool {
	return d.IPv4Addr == (netip.Prefix{}) &&
		d.IPv6Addr == (netip.Prefix{}) &&
		d.IPPool == "" &&
		d.Routes == nil &&
		d.Vlan == 0
}

type SerializedDevice struct {
	Manager DeviceManagerType
	Dev     json.RawMessage
	Config  DeviceConfig
}
