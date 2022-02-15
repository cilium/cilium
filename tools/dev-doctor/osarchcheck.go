// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

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
