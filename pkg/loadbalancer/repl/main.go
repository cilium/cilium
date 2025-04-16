// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package main

import (
	"os"

	uhive "github.com/cilium/hive"
	"github.com/cilium/hive/cell"
	"github.com/cilium/statedb"
	"github.com/spf13/pflag"

	daemonk8s "github.com/cilium/cilium/daemon/k8s"
	"github.com/cilium/cilium/pkg/datapath/tables"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/loadbalancer"
	lbcell "github.com/cilium/cilium/pkg/loadbalancer/cell"
	"github.com/cilium/cilium/pkg/maglev"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/source"
)

// This is a simple read-print-eval-loop for the load-balancing sub-system
// for educational purposes.
//
// To run first start a kind cluster:
//
//	cilium$ make kind
//
// Then run the repl application and start:
//
//	repl$ go run . --k8s-kubeconfig-path=$HOME/.kube/config
//	load-balancer> hive/start
//
// The app should now have connected to the kube apiserver and pulled
// Services and Endpoints and populated the in-memory BPF fake maps (or
// unpinned real BPF maps if you're running as root).
//
// Running 'help' will show what commands are supported. The 'help' command
// takes a regex to look up docs on specific commands:
//
//	load-balancer> help
//	...
//	load-balancer> help db
//	load-balancer> help lb
//
// We can use the 'db' command to show all tables and the 'db/show' command to
// inspect the load-balancing state:
//
//	load-balancer> db
//	...
//	load-balancer> db/show services
//	load-balancer> db/show frontends
//	load-balancer> db/show backends
//
// The 'health' table contains information about jobs that are running:
//
//	load-balancer> db/show health
//
// The 'db/watch' allows watching for changes (ctrl-c will stop). Try launching
// a new pod while running this:
//
//	load-balancer> db/watch frontends
//
// The contents of the BPF maps can be inspected with 'lb/maps-dump':
//
//	load-balancer> lb/maps-dump
//
// These commands are also part of the "cilium-dbg shell" command in the cilium-agent
// deployment.
func main() {
	h := hive.New(
		client.Cell,
		daemonk8s.ResourcesCell,
		daemonk8s.TablesCell,
		maglev.Cell,
		node.LocalNodeStoreCell,
		cell.Provide(source.NewSources),
		cell.Provide(
			tables.NewNodeAddressTable,
			statedb.RWTable[tables.NodeAddress].ToTable,
			func() *option.DaemonConfig {
				return &option.DaemonConfig{
					EnableIPv4:           true,
					EnableIPv6:           true,
					KubeProxyReplacement: option.KubeProxyReplacementTrue,
				}
			},
			func() *loadbalancer.TestConfig {
				return &loadbalancer.TestConfig{}
			},
		),
		cell.Invoke(statedb.RegisterTable[tables.NodeAddress]),
		lbcell.Cell,
	)
	h.RegisterFlags(pflag.CommandLine)
	pflag.Parse()
	uhive.RunRepl(h, os.Stdin, os.Stdout, "load-balancer> ")
}
