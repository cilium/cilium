// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package main

import (
	"os"

	upstreamHive "github.com/cilium/hive"
	"github.com/cilium/hive/cell"
	"github.com/cilium/statedb"

	daemonk8s "github.com/cilium/cilium/daemon/k8s"
	"github.com/cilium/cilium/pkg/datapath/tables"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/loadbalancer/experimental"
	"github.com/cilium/cilium/pkg/maglev"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/source"
)

func main() {
	h := hive.New(
		client.FakeClientCell,
		daemonk8s.ResourcesCell,
		maglev.Cell,
		experimental.Cell,
		cell.Provide(source.NewSources),
		cell.Provide(
			tables.NewNodeAddressTable,
			statedb.RWTable[tables.NodeAddress].ToTable,
			func() *option.DaemonConfig {
				return &option.DaemonConfig{
					LBMapEntries: 1000,
				}
			},
			func() *experimental.TestConfig {
				return &experimental.TestConfig{}
			},
		),
		cell.Invoke(statedb.RegisterTable[tables.NodeAddress]),
	)
	upstreamHive.AddConfigOverride(
		h,
		func(c *experimental.Config) { c.EnableExperimentalLB = true },
	)

	upstreamHive.RunRepl(h, os.Stdin, os.Stdout, "loadbalancer> ")
}
