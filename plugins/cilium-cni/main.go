// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package main

import (
	"runtime"

	"github.com/cilium/cilium/plugins/cilium-cni/cmd"
)

func init() {
	runtime.LockOSThread()
}

func main() {
	cmd.PluginMain()
}
