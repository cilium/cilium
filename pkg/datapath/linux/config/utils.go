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
