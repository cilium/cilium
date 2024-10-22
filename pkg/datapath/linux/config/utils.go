// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package config

import (
	"fmt"
	"net"

	"github.com/cilium/cilium/pkg/byteorder"
	"github.com/cilium/cilium/pkg/common"
)

// FmtDefineAddress returns the a define string from the given name and addr.
// Example:
// fmt.Print(FmtDefineAddress("foo", []byte{1, 2, 3})) // "#define foo { .addr = { 0x1, 0x2, 0x3 } }\n"
func FmtDefineAddress(name string, addr []byte) string {
	return fmt.Sprintf("#define %s { .addr = { %s } }\n", name, common.GoArray2C(addr))
}

// defineUint16 writes the C definition for an unsigned 16-bit value.
func defineUint16(name string, value uint16) string {
	return fmt.Sprintf("DEFINE_U16(%s, %#04x);\t/* %d */\n#define %s fetch_u16(%s)\n",
		name, value, value, name, name)
}

// defineUint32 writes the C definition for an unsigned 32-bit value.
func defineUint32(name string, value uint32) string {
	return fmt.Sprintf("DEFINE_U32(%s, %#08x);\t/* %d */\n#define %s fetch_u32(%s)\n",
		name, value, value, name, name)
}

// defineUint64 writes the C definition for an unsigned 64-bit value.
func defineUint64(name string, value uint64) string {
	return fmt.Sprintf("DEFINE_U64(%s, %#016x);\t/* %d */\n#define %s fetch_u64(%s)\n",
		name, value, value, name, name)
}

// defineIPv4 writes the C definition for the given IPv4 address.
func defineIPv4(name string, addr []byte) string {
	if len(addr) != net.IPv4len {
		return fmt.Sprintf("/* BUG: bad ip define %s %s */\n", name, common.GoArray2C(addr))
	}
	nboAddr := byteorder.NetIPv4ToHost32(addr)
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

// declareConfig writes the C macro for declaring a global configuration variable that can be
// modified at runtime.
func declareConfig(name string, value any, description string) string {
	var t string
	switch value.(type) {
	case uint16:
		t = "__u16"
	case uint32:
		t = "__u32"
	case uint64:
		t = "__u64"
	default:
		return fmt.Sprintf("/* BUG: %s has invalid type for DECLARE_CONFIG: %T*/\n", name, value)
	}
	return fmt.Sprintf("DECLARE_CONFIG(%s, %s, \"%s\");\n", t, name, description)
}

// assignConfig writes the C macro for assigning a value to the given config variable at compile
// time. This value can be overridden at runtime.
func assignConfig(name string, value any) string {
	var t string
	switch value.(type) {
	case uint16:
		t = "__u16"
	case uint32:
		t = "__u32"
	case uint64:
		t = "__u64"
	default:
		return fmt.Sprintf("/* BUG: %s has invalid type for ASSIGN_CONFIG: %T/*\n", name, value)
	}
	return fmt.Sprintf("ASSIGN_CONFIG(%s, %s, %v);\n", t, name, value)
}
