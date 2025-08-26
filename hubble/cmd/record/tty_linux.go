// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

//go:build linux

package record

import (
	"fmt"
	"io"
	"os"

	"golang.org/x/sys/unix"
)

const resetSequence = "\033[A\033[2K"

// isTTY returns true if output f is a terminal
func isTTY(f *os.File) bool {
	_, err := unix.IoctlGetTermios(int(f.Fd()), unix.TCGETS)
	return err == nil
}

// resetLastLine clears the last line printed on the output f
func clearLastLine(f io.Writer) {
	fmt.Fprint(f, resetSequence)
}
