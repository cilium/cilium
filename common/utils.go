// Copyright 2016-2019 Authors of Cilium
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
	"io/ioutil"
	"os"
	"path/filepath"
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
		digit, err := strconv.ParseInt(strDigit, 16, 9)
		if err != nil {
			return nil
		}
		ret = append(ret, byte(digit))
	}
	return ret
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

// MoveNewFilesTo copies all files, that do not exist in newDir, from oldDir.
func MoveNewFilesTo(oldDir, newDir string) error {
	oldFiles, err := ioutil.ReadDir(oldDir)
	if err != nil {
		return err
	}
	newFiles, err := ioutil.ReadDir(newDir)
	if err != nil {
		return err
	}

	for _, oldFile := range oldFiles {
		exists := false
		for _, newFile := range newFiles {
			if oldFile.Name() == newFile.Name() {
				exists = true
				break
			}
		}
		if !exists {
			os.Rename(filepath.Join(oldDir, oldFile.Name()), filepath.Join(newDir, oldFile.Name()))
		}
	}
	return nil
}

// MapStringStructToSlice returns a slice with all keys of the given
// map[string]struct{}
func MapStringStructToSlice(m map[string]struct{}) []string {
	s := make([]string, 0, len(m))
	for k := range m {
		s = append(s, k)
	}
	return s
}
