// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package main

import (
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/standalone-dns-proxy/cmd"
)

func main() {
	standaloneDNSProxyHive := hive.New(cmd.StandaloneDNSProxyCell)

	cmd.Execute(cmd.NewDNSProxyCmd(standaloneDNSProxyHive))
}
