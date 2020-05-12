// Copyright 2019 Authors of Cilium
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

package config

import (
	"fmt"
	"net"
	"reflect"

	"github.com/cilium/cilium/pkg/byteorder"
	"github.com/cilium/cilium/pkg/common"
)

// FmtDefineAddress returns the a define string from the given name and addr.
// Example:
// fmt.Print(FmtDefineAddress("foo", []byte{1, 2, 3})) // "#define foo { .addr = { 0x1, 0x2, 0x3 } }\n"
func FmtDefineAddress(name string, addr []byte) string {
	return fmt.Sprintf("#define %s { .addr = { %s } }\n", name, common.GoArray2C(addr))
}

// defineUint32 writes the C definition for an unsigned 32-bit value.
func defineUint32(name string, value uint32) string {
	return fmt.Sprintf("DEFINE_U32(%s, %#08x);\t/* %d */\n#define %s fetch_u32(%s)\n",
		name, value, value, name, name)
}

// defineIPv4 writes the C definition for the given IPv4 address.
func defineIPv4(name string, addr []byte) string {
	if len(addr) != net.IPv4len {
		return fmt.Sprintf("/* BUG: bad ip define %s %s */\n", name, common.GoArray2C(addr))
	}
	nboAddr := byteorder.HostSliceToNetwork(addr, reflect.Uint32).(uint32)
	return defineUint32(name, nboAddr)
}

// defineIPv6 writes the C definition for the given IPv6 address.
func defineIPv6(name string, addr []byte) string {
	if len(addr) != net.IPv6len {
		return fmt.Sprintf("/* BUG: bad ip define %s %s */\n", name, common.GoArray2C(addr))
	}
	return fmt.Sprintf("DEFINE_IPV6(%s, %s);\n#define %s_V\n",
		name, common.GoArray2C(addr), name)
}

func dumpRaw(name string, addr []byte) string {
	return fmt.Sprintf(" %s%s\n", name, common.GoArray2C(addr))
}

// defineMAC writes the C definition for the given MAC name and addr.
func defineMAC(name string, addr []byte) string {
	if len(addr) != 6 { /* MAC len */
		return fmt.Sprintf("/* BUG: bad mac define %s %s */\n", name, common.GoArray2C(addr))
	}
	return fmt.Sprintf("DEFINE_MAC(%s, %s);\n#define %s fetch_mac(%s)\n",
		name, common.GoArray2C(addr), name, name)
}
