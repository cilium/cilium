// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package main

import "github.com/cilium/cilium/etcd-init/cmd"

func main() {
	cmd.New().Execute()
}
