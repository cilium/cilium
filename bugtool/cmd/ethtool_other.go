// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build !linux

package cmd

func ethtoolCommands() []string {
	// No op so the code compiles on non-Linux platforms.
	return nil
}
