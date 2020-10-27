// Copyright 2020 Authors of Cilium
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

package main

import "runtime"

// An osArchCheck checks that runtime.GOOS and runtime.GOARCH are supported.
type osArchCheck struct{}

func (osArchCheck) Name() string {
	return "os/arch"
}

func (osArchCheck) Run() (checkResult, string) {
	osArch := runtime.GOOS + "/" + runtime.GOARCH
	switch runtime.GOOS {
	case "darwin":
		return checkWarning, osArch
	case "linux":
		switch runtime.GOARCH {
		case "amd64":
			return checkOK, osArch
		default:
			return checkWarning, osArch
		}
	default:
		return checkError, osArch
	}
}

func (osArchCheck) Hint() string {
	return ""
}
