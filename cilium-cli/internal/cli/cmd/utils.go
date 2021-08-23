// SPDX-License-Identifier: Apache-2.0
// Copyright 2020-2021 Authors of Cilium

package cmd

import (
	"fmt"
	"os"
)

// fatalf prints the Printf formatted message to stderr and exits the program
// Note: os.Exit(1) is not recoverable and does not fire defers.
func fatalf(msg string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, "\nError: %s\n", fmt.Sprintf(msg, args...))
	os.Exit(1)
}
