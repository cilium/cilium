// Copyright 2017-2021 Authors of Cilium
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

package byteorder

import (
	"net"
)

// NetIPv4ToHost32 converts an net.IP to a uint32 in host byte order. ip
// must be a IPv4 address, otherwise the function will panic.
func NetIPv4ToHost32(ip net.IP) uint32 {
	ipv4 := ip.To4()
	_ = ipv4[3] // Assert length of ipv4.
	return Native.Uint32(ipv4)
}
