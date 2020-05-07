// Copyright 2016-2018 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// +build darwin

package route

import (
	"fmt"

	"github.com/cilium/cilium/pkg/mtu"

	"github.com/vishvananda/netlink"
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
