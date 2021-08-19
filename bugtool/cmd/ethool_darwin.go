// SPDX-License-Identifier: Apache-2.0
// Copyright 2017-2018 Authors of Cilium

//go:build darwin
// +build darwin

package cmd

func ethoolCommands() []string {
	// No op so the code compiles on macOS
	return []string{}
}
