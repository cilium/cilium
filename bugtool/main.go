// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

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
