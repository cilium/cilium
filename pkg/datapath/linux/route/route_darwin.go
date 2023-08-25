// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build darwin

package route

import (
	"fmt"

	"github.com/vishvananda/netlink"

	"github.com/cilium/cilium/pkg/mtu"
)

// errUnsupportedOp is a common error
var errUnsupportedOp = fmt.Errorf("Route operations not supported on Darwin")

// Replace is not supported on Darwin and will return an error at runtime.
func Replace(route Route, mtuConfig mtu.Configuration) error {
	return errUnsupportedOp
}

// Delete is not supported on Darwin and will return an error at runtime.
func Delete(route Route) error {
	return errUnsupportedOp
}

// NodeDeviceWithDefaultRoute is not supported on Darwin and will return
// an error at runtime.
func NodeDeviceWithDefaultRoute(enableIPv4, enableIPv6 bool) (netlink.Link, error) {
	return nil, errUnsupportedOp
}
