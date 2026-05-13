// Copyright (C) 2014, 2015 Nippon Telegraph and Telephone Corporation.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
// implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package zebra

import (
	"strings"
	"syscall"
)

func intfflag2string(flag uint64) string {
	ss := make([]string, 0, 10)
	if flag&syscall.IFF_UP > 0 {
		ss = append(ss, "UP")
	}
	if flag&syscall.IFF_BROADCAST > 0 {
		ss = append(ss, "BROADCAST")
	}
	if flag&syscall.IFF_DEBUG > 0 {
		ss = append(ss, "DEBUG")
	}
	if flag&syscall.IFF_LOOPBACK > 0 {
		ss = append(ss, "LOOPBACK")
	}
	if flag&syscall.IFF_POINTOPOINT > 0 {
		ss = append(ss, "POINTOPOINT")
	}
	if flag&syscall.IFF_NOTRAILERS > 0 {
		ss = append(ss, "NOTRAILERS")
	}
	if flag&syscall.IFF_RUNNING > 0 {
		ss = append(ss, "RUNNING")
	}
	if flag&syscall.IFF_NOARP > 0 {
		ss = append(ss, "NOARP")
	}
	if flag&syscall.IFF_PROMISC > 0 {
		ss = append(ss, "PROMISC")
	}
	if flag&syscall.IFF_ALLMULTI > 0 {
		ss = append(ss, "ALLMULTI")
	}
	if flag&syscall.IFF_MASTER > 0 {
		ss = append(ss, "MASTER")
	}
	if flag&syscall.IFF_SLAVE > 0 {
		ss = append(ss, "SLAVE")
	}
	if flag&syscall.IFF_MULTICAST > 0 {
		ss = append(ss, "MULTICAST")
	}
	if flag&syscall.IFF_PORTSEL > 0 {
		ss = append(ss, "PORTSEL")
	}
	if flag&syscall.IFF_AUTOMEDIA > 0 {
		ss = append(ss, "AUTOMEDIA")
	}
	if flag&syscall.IFF_DYNAMIC > 0 {
		ss = append(ss, "DYNAMIC")
	}
	//	if flag&syscall.IFF_LOWER_UP > 0 {
	//		ss = append(ss, "LOWER_UP")
	//	}
	//	if flag&syscall.IFF_DORMANT > 0 {
	//		ss = append(ss, "DORMANT")
	//	}
	//	if flag&syscall.IFF_ECHO > 0 {
	//		ss = append(ss, "ECHO")
	//	}
	return strings.Join(ss, " | ")
}
