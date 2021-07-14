// SPDX-License-Identifier: Apache-2.0
// Copyright 2020 Authors of Cilium

// Command doctor checks the development setup for common problems.
package main

import (
	"fmt"
	"os"
)

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
