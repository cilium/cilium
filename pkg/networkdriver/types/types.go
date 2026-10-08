// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package types

import (
	"context"
	"encoding"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"strings"

	resourceapi "k8s.io/api/resource/v1"
	"k8s.io/dynamic-resource-allocation/deviceattribute"

	"github.com/cilium/cilium/pkg/datapath/linux/sysctl"
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
	// DeviceManagerLabel identifies which Device Manager
	// published the device.
	DeviceManagerLabel = "deviceManager"
	// PoolNameLabel is the pool name.
	PoolNameLabel = "pool"
	// PCIBusIDLabel contains the PCI bus address for
	// the device. Only applicable to PCI based devices.
	PCIBusIDLabel = deviceattribute.StandardDeviceAttributePrefix + "pciBusID"
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
)

var (
	errUnknownDeviceManagerType = errors.New("unknown device manager type")
	errInvalidSysctlLeaf        = errors.New("invalid sysctl leaf parameter")
	errEmptySysctlValue         = errors.New("sysctl value must not be empty")
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

// validateInterfaceSysctl validates a device config's interface-scoped
// sysctl leaves at claim preparation time: pure, no I/O. Only the leaf
// (e.g. "arp_filter") is user-controlled; the net.<family>.conf.<interface>.
// prefix is added later, in buildSysctlSettings, once the allocated
// interface's final name is known.
func (cfg *DeviceConfig) validateInterfaceSysctl() error {
	if err := validateSysctlLeaves(cfg.InterfaceSysctlIPv4); err != nil {
		return fmt.Errorf("ipv4: %w", err)
	}
	if err := validateSysctlLeaves(cfg.InterfaceSysctlIPv6); err != nil {
		return fmt.Errorf("ipv6: %w", err)
	}
	return nil
}

func validateSysctlLeaves(leaves map[string]string) error {
	for leaf, val := range leaves {
		if err := sysctl.ValidateParameter(strings.Split(leaf, ".")); err != nil {
			return fmt.Errorf("%w: %q: %w", errInvalidSysctlLeaf, leaf, err)
		}
		if val == "" {
			return fmt.Errorf("%w: %q", errEmptySysctlValue, leaf)
		}
	}
	return nil
}

// validateInterfaceName validates an interface name according to Linux rules
func validateInterfaceName(name string) error {
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
	// DeviceManagerTypeMock is a sentinel used by unit tests.
	// It is intentionally kept in the types package so that test files in
	// the networkdriver package can reference it without importing a real
	// device-manager package.
	DeviceManagerTypeMock DeviceManagerType = iota
	DeviceManagerTypeDummy
	DeviceManagerTypeSRIOV
	DeviceManagerTypeUnknown
)

const (
	deviceManagerTypeMockStr = "mock"
	dummyDeviceManagerStr    = "dummy"
	sriovDeviceManagerStr    = "sr-iov"
)

func (d DeviceManagerType) String() string {
	switch d {
	case DeviceManagerTypeMock:
		return deviceManagerTypeMockStr

	case DeviceManagerTypeDummy:
		return dummyDeviceManagerStr

	case DeviceManagerTypeSRIOV:
		return sriovDeviceManagerStr
	}

	return ""
}

func (d DeviceManagerType) MarshalText() (text []byte, err error) {
	switch d {
	case DeviceManagerTypeMock:
		return []byte(deviceManagerTypeMockStr), nil

	case DeviceManagerTypeDummy:
		return []byte(dummyDeviceManagerStr), nil

	case DeviceManagerTypeSRIOV:
		return []byte(sriovDeviceManagerStr), nil
	}

	return nil, errUnknownDeviceManagerType
}

func (d *DeviceManagerType) UnmarshalText(text []byte) error {
	switch strings.ToLower(string(text)) {
	case deviceManagerTypeMockStr:
		*d = DeviceManagerTypeMock
	case dummyDeviceManagerStr:
		*d = DeviceManagerTypeDummy
	case sriovDeviceManagerStr:
		*d = DeviceManagerTypeSRIOV
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
	Merge(Device)
}

type DeviceManager interface {
	Type() DeviceManagerType
	// Run publishes the current device set by calling publish, then blocks
	// until ctx is cancelled. Implementations must call publish at least once
	// before returning so the driver knows what devices are available.
	// On any change to the device set, Run calls publish again with the full
	// updated set.
	Run(ctx context.Context, publish func([]Device)) error
	RestoreDevice([]byte) (Device, error)
}

type DeviceConfig struct {
	PodIfName string       `json:"podIfName,omitempty"` // Custom interface name for the pod namespace
	Vlan      int32        `json:"vlan,omitempty"`      // VLAN ID to assign to the device (0 = untagged / no change)
	IPv4Addr  netip.Prefix `json:"ipv4Addr,omitzero"`
	IPv6Addr  netip.Prefix `json:"ipv6Addr,omitzero"`
	IPPool    string       `json:"ipPool,omitempty"`

	// InterfaceSysctlIPv4/IPv6 hold leaf sysctl parameters (e.g.
	// "arp_filter") applied under net.<family>.conf.<interface>. for the
	// interface this claim allocates. Applied once, inside the pod netns,
	// when the interface is brought up; not reverted on Free (the
	// namespace is destroyed with the pod).
	InterfaceSysctlIPv4 map[string]string `json:"interfaceSysctlIPv4,omitempty"`
	InterfaceSysctlIPv6 map[string]string `json:"interfaceSysctlIPv6,omitempty"`
}

func (d *DeviceConfig) Validate() error {
	if d == nil {
		return fmt.Errorf("device config is nil")
	}

	if err := validateInterfaceName(d.PodIfName); err != nil {
		return fmt.Errorf("invalid podIfName: %w", err)
	}

	if err := d.validateInterfaceSysctl(); err != nil {
		return fmt.Errorf("invalid sysctl config: %w", err)
	}
	return nil
}

func (d *DeviceConfig) Empty() bool {
	if d == nil {
		return true
	}
	return d.PodIfName == "" &&
		d.Vlan == 0 &&
		!d.IPv4Addr.IsValid() &&
		!d.IPv6Addr.IsValid() &&
		d.IPPool == "" &&
		len(d.InterfaceSysctlIPv4) == 0 &&
		len(d.InterfaceSysctlIPv6) == 0
}

func (d *DeviceConfig) HasPool() bool {
	return d.IPPool != ""
}

type SerializedDevice struct {
	Manager DeviceManagerType
	Dev     json.RawMessage
	Config  DeviceConfig
}
