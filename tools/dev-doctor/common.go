// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package main

import (
	"go/build"
	"os"
)

// goPath returns the environment $GOPATH, or the default when empty or unset.
func goPath() string {
	if gp := os.Getenv("GOPATH"); gp != "" {
		return gp
	}
	return build.Default.GOPATH
}
