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
//
// +build linux

package sysctl

import (
	"fmt"
	"io/ioutil"
	"path/filepath"
	"strings"
)

const (
	prefixDir = "/proc/sys"
)

func fullPath(name string) string {
	return filepath.Join(prefixDir, strings.Replace(name, ".", "/", -1))
}

func readSysctl(name string) ([]byte, error) {
	fPath := fullPath(name)
	b, err := ioutil.ReadFile(fPath)
	if err != nil {
		return nil, fmt.Errorf("could not read the sysctl file %s: %s",
			fPath, err)
	}
	return b[:], nil
}

func writeSysctl(name string, value []byte) error {
	fPath := fullPath(name)
	if err := ioutil.WriteFile(fPath, value, 0644); err != nil {
		return fmt.Errorf("could not write to the systctl file %s: %s",
			fPath, err)
	}
	return nil
}

// Disable disables the given sysctl parameter.
func Disable(name string) error {
	return writeSysctl(name, []byte("0"))
}

// Enable enables the given sysctl parameter.
func Enable(name string) error {
	return writeSysctl(name, []byte("1"))
}
