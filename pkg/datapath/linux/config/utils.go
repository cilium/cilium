// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package config

import (
	"fmt"

	"github.com/cilium/cilium/pkg/common"
)

// FmtDefineAddress returns the a define string from the given name and addr.
// Example:
// fmt.Print(FmtDefineAddress("foo", []byte{1, 2, 3})) // "#define foo { .addr = { 0x1, 0x2, 0x3 } }\n"
func FmtDefineAddress(name string, addr []byte) string {
	return fmt.Sprintf("#define %s { .addr = { %s } }\n", name, common.GoArray2C(addr))
}

func dumpRaw(name string, addr []byte) string {
	return fmt.Sprintf(" %s%s\n", name, common.GoArray2C(addr))
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
