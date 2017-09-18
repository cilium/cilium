// Copyright 2016-2017 Authors of Cilium
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

package common

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// goArray2C transforms a byte slice into its hexadecimal string representation.
// Example:
// array := []byte{0x12, 0xFF, 0x0, 0x01}
// fmt.Print(GoArray2C(array)) // "{ 0x12, 0xff, 0x0, 0x1 }"
func goArray2C(array []byte) string {
	ret := ""

	for i, e := range array {
		if i == 0 {
			ret = ret + fmt.Sprintf("%#x", e)
		} else {
			ret = ret + fmt.Sprintf(", %#x", e)
		}
	}
	return ret
}

func FmtDefineComma(name string, addr []byte) string {
	return fmt.Sprintf("#define %s %s\n", name, goArray2C(addr))
}

// FmtDefineAddress returns the a define string from the given name and addr.
// Example:
// fmt.Print(FmtDefineAddress("foo", []byte{1, 2, 3})) // "#define foo { .addr = { 0x1, 0x2, 0x3 } }\n"
func FmtDefineAddress(name string, addr []byte) string {
	return fmt.Sprintf("#define %s { .addr = { %s } }\n", name, goArray2C(addr))
}

// FmtDefineArray returns the a define string from the given name and array.
// Example:
// fmt.Print(FmtDefineArray("foo", []byte{1, 2, 3})) // "#define foo { 0x1, 0x2, 0x3 }\n"
func FmtDefineArray(name string, array []byte) string {
	return fmt.Sprintf("#define %s { %s }\n", name, goArray2C(array))
}

// FindEPConfigCHeader returns the full path of the file that is the CHeaderFileName from
// the slice of files
func FindEPConfigCHeader(basePath string, epFiles []os.FileInfo) string {
	for _, epFile := range epFiles {
		if epFile.Name() == CHeaderFileName {
			return filepath.Join(basePath, epFile.Name())
		}
	}
	return ""
}

// GetCiliumVersionString returns the first line containing CiliumCHeaderPrefix.
func GetCiliumVersionString(epCHeaderFilePath string) (string, error) {
	f, err := os.Open(epCHeaderFilePath)
	if err != nil {
		return "", err
	}
	br := bufio.NewReader(f)
	defer f.Close()
	for {
		s, err := br.ReadString('\n')
		if err == io.EOF {
			return "", nil
		}
		if err != nil {
			return "", err
		}
		if strings.Contains(s, CiliumCHeaderPrefix) {
			return s, nil
		}
	}
}

// RequireRootPrivilege checks if the user running cmd is root. If not, it exits the program
func RequireRootPrivilege(cmd string) {
	if os.Getuid() != 0 {
		fmt.Fprintf(os.Stderr, "Please run %q command(s) with root privileges.\n", cmd)
		os.Exit(1)
	}
}
