// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package main

import (
	"os"
	"slices"
	"strings"

	uhive "github.com/cilium/hive"
	"github.com/cilium/hive/cell"
	"github.com/cilium/statedb"
	"github.com/spf13/pflag"

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
	// If the k8s-kubeconfig-path is given use the real client.
	k8sClientCell := client.FakeClientCell
	if strings.Contains(strings.Join(os.Args, " "), "k8s-kubeconfig-path") {
		k8sClientCell = client.Cell
	}

	h := hive.New(
		k8sClientCell,
		daemonk8s.ResourcesCell,
		maglev.Cell,
		experimental.Cell,
		cell.Provide(
			source.NewSources,
			tables.NewNodeAddressTable,
			statedb.RWTable[tables.NodeAddress].ToTable,
			func() *option.DaemonConfig {
				return &option.DaemonConfig{
					LBMapEntries: 10000,
				}
			},
			func() *experimental.TestConfig {
				return &experimental.TestConfig{}
			},
		),
		cell.Invoke(statedb.RegisterTable[tables.NodeAddress]),
	)

	fs := pflag.NewFlagSet("repl", pflag.ExitOnError)
	h.RegisterFlags(fs)
	extraArgs := []string{
		"--enable-experimental-lb=true",
	}
	fs.Parse(slices.Concat(os.Args[1:], extraArgs))

	uhive.RunRepl(h, os.Stdin, os.Stdout, "loadbalancer> ")
}
