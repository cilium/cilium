// Copyright 2015 CNI authors
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

package ip

import (
	"net"

	"github.com/vishvananda/netlink"
)

// AddDefaultRoute sets the default route on the given gateway.
func AddDefaultRoute(gw net.IP, dev netlink.Link) error {
	_, defNet, _ := net.ParseCIDR("0.0.0.0/0")
	return AddRoute(defNet, gw, dev)
}
