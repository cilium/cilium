// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

// Ensure build fails on versions of Go that are not supported by Cilium.
// This build tag should be kept in sync with the version specified in go.mod.
//go:build go1.20

package main

import "github.com/cilium/cilium/cilium-health/cmd"

func main() {
	cmd.Execute()
}
