// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package inl

import (
	"fmt"

	"github.com/vishvananda/netlink"
)

var defaultOptions = netlink.HandleOptions{
	DisableVFInfoCollection: true,
	RetryInterrupted:        true,
}

func init() {
	if err := netlink.ConfigureHandle(defaultOptions); err != nil {
		panic(fmt.Sprintf("configuring global netlink handle: %s", err))
	}
}

// NewHandle returns a [netlink.Handle] created using default handle options.
func NewHandle(families ...int) (*netlink.Handle, error) {
	//nolint:forbidigo
	handle, err := netlink.NewHandleWithOptions(defaultOptions, families...)
	if err != nil {
		return nil, err
	}

	return handle, nil
}
