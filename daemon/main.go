// SPDX-License-Identifier: Apache-2.0
// Copyright 2016-2020 Authors of Cilium

// Ensure build fails on versions of Go that are not supported by Cilium.
// This build tag should be kept in sync with the version specified in go.mod.
//go:build go1.17
// +build go1.17

package main

import (
	"github.com/cilium/cilium/daemon/cmd"
)

func main() {
	cmd.Execute()
}
