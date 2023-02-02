// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

// Ensure build fails on versions of Go that are not supported by Cilium.
// This build tag should be kept in sync with the version specified in go.mod.
//go:build go1.20

package main

import (
	"fmt"
	"os"

	"github.com/cilium/cilium/bugtool/cmd"
)

func main() {
	if err := cmd.BugtoolRootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
