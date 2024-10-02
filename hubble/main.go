// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package main

import (
	"fmt"
	"os"

	"github.com/cilium/cilium/hubble/cmd"
)

func main() {
	if err := cmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}
}
