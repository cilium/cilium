// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package common

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

// C2GoArray transforms an hexadecimal string representation into a byte slice.
// Example:
// str := "0x12, 0xff, 0x0, 0x1"
// fmt.Print(C2GoArray(str)) //`{0x12, 0xFF, 0x0, 0x01}`"
func C2GoArray(str string) []byte {
	ret := []byte{}

	if str == "" {
		return ret
	}

	hexStr := strings.Split(str, ", ")
	for _, hexDigit := range hexStr {
		strDigit := strings.TrimPrefix(hexDigit, "0x")
		digitUint64, err := strconv.ParseUint(strDigit, 16, 8)
		if err != nil {
			return nil
		}
		ret = append(ret, byte(digitUint64))
	}
	return ret
}

// GoArray2C transforms a byte slice into its hexadecimal string representation.
// Example:
// array := []byte{0x12, 0xFF, 0x0, 0x01}
// fmt.Print(GoArray2C(array)) // "{ 0x12, 0xff, 0x0, 0x1 }"
func GoArray2C(array []byte) string {
	return goArray2C(array, true)
}

// GoArray2CNoSpaces does the same as GoArray2C, but no spaces are used in
// the final output.
// Example:
// array := []byte{0x12, 0xFF, 0x0, 0x01}
// fmt.Print(GoArray2CNoSpaces(array)) // "{0x12,0xff,0x0,0x1}"
func GoArray2CNoSpaces(array []byte) string {
	return goArray2C(array, false)
}

func goArray2C(array []byte, space bool) string {
	ret := ""
	format := ",%#x"
	if space {
		format = ", %#x"
	}

	for i, e := range array {
		if i == 0 {
			ret = ret + fmt.Sprintf("%#x", e)
		} else {
			ret = ret + fmt.Sprintf(format, e)
		}
	}
	return ret
}

// RequireRootPrivilege checks if the user running cmd is root. If not, it exits the program
func RequireRootPrivilege(cmd string) {
	if os.Getuid() != 0 {
		fmt.Fprintf(os.Stderr, "Please run %q command(s) with root privileges.\n", cmd)
		os.Exit(1)
	}
}
