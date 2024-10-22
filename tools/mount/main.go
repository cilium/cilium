// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package main

import (
	"fmt"
	"os"

	"github.com/cilium/cilium/pkg/cgroups"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintf(os.Stderr, "usage: %s <cgroup-mount-point> \n\n", os.Args[0])
		os.Exit(1)
	}

	cgroupMountPoint := os.Args[1]
	// This program is executed by an init container so we purposely don't
	// exit with any error codes. In case of errors, the function will log warnings,
	// but we don't block cilium agent pod from running.
	cgroups.CheckOrMountCgrpFS(cgroupMountPoint)
}
