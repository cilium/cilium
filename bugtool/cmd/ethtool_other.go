// SPDX-License-Identifier: Apache-2.0
// Copyright 2017-2018 Authors of Cilium

//go:build !linux
// +build !linux

package cmd

func ethtoolCommands() []string {
	// No op so the code compiles on non-Linux platforms.
	return nil
}
