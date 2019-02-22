// Copyright 2016-2018 Authors of Cilium
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

package probes

import (
	"bytes"
	"fmt"
	"regexp"
	"strings"

	go_version "github.com/hashicorp/go-version"
	"golang.org/x/sys/unix"
)

func getKernelVersionStr() string {
	var unameBuf unix.Utsname
	if err := unix.Uname(&unameBuf); err != nil {
		log.WithError(err).Fatal("kernel version: NOT OK")
	}
	return string(bytes.Trim(unameBuf.Release[:], "\x00"))
}

func parseKernelVersion(ver string) (*go_version.Version, error) {
	verStrs := strings.Split(ver, ".")
	switch {
	case len(verStrs) < 2:
		return nil, fmt.Errorf("unable to get kernel version from %q", ver)
	case len(verStrs) < 3:
		verStrs = append(verStrs, "0")
	}
	// We are assuming the kernel version will be something as:
	// 4.9.17-040917-generic

	// If verStrs is []string{ "4", "9", "17-040917-generic" }
	// then we need to retrieve patch number.
	patch := regexp.MustCompilePOSIX(`^[0-9]+`).FindString(verStrs[2])
	if patch == "" {
		verStrs[2] = "0"
	} else {
		verStrs[2] = patch
	}
	return go_version.NewVersion(strings.Join(verStrs[:3], "."))
}

// GetKernelVersion returns the version of currently used Linux kernel.
func GetKernelVersion() (*go_version.Version, error) {
	kernelVersionStr := getKernelVersionStr()
	return parseKernelVersion(kernelVersionStr)
}
