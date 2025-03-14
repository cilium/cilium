// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package main

import (
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/standalone-dns-proxy/cmd"
)

func main() {
	dnsProxyHive := hive.New(cmd.DNSProxy)

	cmd.Execute(cmd.NewDNSProxyCmd(dnsProxyHive))
}
