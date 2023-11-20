// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package main

import (
	"runtime"

	"github.com/containernetworking/cni/pkg/skel"
	cniVersion "github.com/containernetworking/cni/pkg/version"

	"github.com/cilium/cilium/pkg/version"
	"github.com/cilium/cilium/plugins/cilium-cni/cmd"
)

func init() {
	runtime.LockOSThread()
}

func main() {
	skel.PluginMain(cmd.Add,
		cmd.Check,
		cmd.Del,
		cniVersion.PluginSupports("0.1.0", "0.2.0", "0.3.0", "0.3.1", "0.4.0", "1.0.0"),
		"Cilium CNI plugin "+version.Version)
}
