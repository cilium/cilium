// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package types

import (
	"encoding/json"
	"errors"
	"net/netip"
	"strings"

	resourceapi "k8s.io/api/resource/v1"

	"github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
)

var (
	errUnknownDriverType = errors.New("unknown driver type")
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

	return nil, errUnknownDriverType
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
		return errUnknownDriverType
	}

	return nil
}

type Device interface {
	GetAttrs() map[resourceapi.QualifiedName]resourceapi.DeviceAttribute
	Setup(cfg DeviceConfig) error
	Free(cfg DeviceConfig) error
	Match(filter v2alpha1.CiliumNetworkDriverDeviceFilter) bool
	IfName() string
	KernelIfName() string
}

type DeviceManager interface {
	ListDevices() ([]Device, error)
}

type DeviceManagerConfig interface {
	IsEnabled() bool
}

type RouteSet map[netip.Prefix]AddrSet

type AddrSet map[netip.Prefix]struct{}

type DeviceConfig struct {
	Ipv4Addr netip.Prefix `json:"ipv4Addr"`
	Routes   RouteSet
	Vlan     uint16
}

func (d *DeviceConfig) Empty() bool {
	return d.Ipv4Addr == (netip.Prefix{}) &&
		d.Routes == nil &&
		d.Vlan == 0
}
