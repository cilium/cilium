// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package types

import (
	"encoding"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"regexp"
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
	// ParentIfNameLabel is the kernel ifname of the parent device.
	ParentIfNameLabel = "parentIfName"
	// MacVlanModeLabel is macvlan mode for a macvlan interface.
	MacVlanModeLabel = "macvlanMode"
)

var (
	errUnknownDeviceManagerType = errors.New("unknown device manager type")
)

// Interface name validation constants
const (
	// MaxInterfaceNameLength is the maximum length for a Linux interface name (IFNAMSIZ - 1)
	MaxInterfaceNameLength = 15
)

var (
	// validIfNameRegex matches valid interface name characters (alphanumeric, dot, underscore, dash)
	validIfNameRegex = regexp.MustCompile(`^[a-zA-Z0-9._-]+$`)
)

// ValidateInterfaceName validates an interface name according to Linux rules
func ValidateInterfaceName(name string) error {
	// Empty name is valid (means no custom rename)
	if name == "" {
		return nil
	}

	// Check length limit (Linux IFNAMSIZ - 1)
	if len(name) > MaxInterfaceNameLength {
		return fmt.Errorf(
			"interface name too long: %q (%d chars, max %d)",
			name, len(name), MaxInterfaceNameLength)
	}

	// Check for valid characters
	if !validIfNameRegex.MatchString(name) {
		return fmt.Errorf(
			"interface name contains invalid characters: %q (allowed: a-z A-Z 0-9 . _ -)",
			name)
	}

	// Check for reserved names
	if name == "lo" {
		return fmt.Errorf("interface name %q is reserved (loopback)", name)
	}

	if len(name) >= 7 && name[:7] == "cilium_" {
		return fmt.Errorf("interface name %q is reserved (cilium_ prefix)", name)
	}

	return nil
}

type DeviceManagerType int

const (
	sriovDeviceManagerStr   = "sr-iov"
	dummyDeviceManagerStr   = "dummy"
	macvlanDeviceManagerStr = "macvlan"
)

const (
	DeviceManagerTypeSRIOV DeviceManagerType = iota
	DeviceManagerTypeDummy
	DeviceManagerTypeMacvlan

	DeviceManagerTypeUnknown
)

func (d DeviceManagerType) String() string {
	switch d {
	case DeviceManagerTypeSRIOV:
		return sriovDeviceManagerStr
	case DeviceManagerTypeDummy:
		return dummyDeviceManagerStr
	case DeviceManagerTypeMacvlan:
		return macvlanDeviceManagerStr
	}

	return ""
}

func (d DeviceManagerType) MarshalText() (text []byte, err error) {
	switch d {
	case DeviceManagerTypeSRIOV:
		return json.Marshal(sriovDeviceManagerStr)
	case DeviceManagerTypeDummy:
		return json.Marshal(dummyDeviceManagerStr)
	case DeviceManagerTypeMacvlan:
		return json.Marshal(macvlanDeviceManagerStr)
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
	case macvlanDeviceManagerStr:
		*d = DeviceManagerTypeMacvlan
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

type Route struct {
	Destination netip.Prefix
	Gateway     netip.Addr
}

type DeviceConfig struct {
	NetworkConfig string       `json:"networkConfig,omitempty"`
	IPv4Addr      netip.Prefix `json:"ipv4Addr,omitempty"`
	IPv6Addr      netip.Prefix `json:"ipv6Addr,omitempty"`
	IPPool        string       `json:"ip-pool,omitempty"`
	Routes        []Route      `json:"routes,omitempty"`
	Vlan          uint16       `json:"vlan,omitempty"`
	PodIfName     string       `json:"podIfName,omitempty"` // Custom interface name for the pod namespace
}

func (d *DeviceConfig) Empty() bool {
	return d.NetworkConfig == "" &&
		d.IPv4Addr == (netip.Prefix{}) &&
		d.IPv6Addr == (netip.Prefix{}) &&
		d.IPPool == "" &&
		d.Routes == nil &&
		d.Vlan == 0 &&
		d.PodIfName == ""
}

type SerializedDevice struct {
	Manager DeviceManagerType
	Dev     json.RawMessage
	Config  DeviceConfig
}
