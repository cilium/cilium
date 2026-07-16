// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package types

import (
	"encoding"
	"encoding/json"
	"errors"
	"fmt"
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
	// HWAddrLabel contains the MAC address of the device.
	HWAddrLabel = "macAddress"
	// DeviceManagerLabel identifies which Device Manager
	// published the device.
	DeviceManagerLabel = "deviceManager"
	// PoolNameLabel is the pool name.
	PoolNameLabel = "pool"
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
	// DeviceManagerTypeMock is a sentinel used by unit tests.
	// It is intentionally kept in the types package so that test files in
	// the networkdriver package can reference it without importing a real
	// device-manager package.
	DeviceManagerTypeMock DeviceManagerType = iota
	DeviceManagerTypeDummy
	DeviceManagerTypeUnknown
)

const (
	deviceManagerTypeMockStr = "mock"
	dummyDeviceManagerStr    = "dummy"
)

func (d DeviceManagerType) String() string {
	switch d {
	case DeviceManagerTypeMock:
		return deviceManagerTypeMockStr

	case DeviceManagerTypeDummy:
		return dummyDeviceManagerStr
	}

	return ""
}

func (d DeviceManagerType) MarshalText() (text []byte, err error) {
	switch d {
	case DeviceManagerTypeMock:
		return json.Marshal(deviceManagerTypeMockStr)

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
	case deviceManagerTypeMockStr:
		*d = DeviceManagerTypeMock
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

type DeviceConfig struct {
	PodIfName string `json:"podIfName,omitempty"` // Custom interface name for the pod namespace
}

func (d *DeviceConfig) Empty() bool {
	return d == nil || *d == DeviceConfig{}
}

type SerializedDevice struct {
	Manager DeviceManagerType
	Dev     json.RawMessage
	Config  DeviceConfig
}
