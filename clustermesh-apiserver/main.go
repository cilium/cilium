// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package main

import (
	"fmt"
	"os"

	"github.com/cilium/hive/cell"
	"github.com/spf13/cobra"

	"github.com/cilium/cilium/clustermesh-apiserver/clustermesh"
	clustermeshdbg "github.com/cilium/cilium/clustermesh-apiserver/clustermesh-dbg"
	"github.com/cilium/cilium/clustermesh-apiserver/etcdinit"
	"github.com/cilium/cilium/clustermesh-apiserver/health"
	"github.com/cilium/cilium/clustermesh-apiserver/kvstoremesh"
	kvstoremeshdbg "github.com/cilium/cilium/clustermesh-apiserver/kvstoremesh-dbg"
	cmmetrics "github.com/cilium/cilium/clustermesh-apiserver/metrics"
	"github.com/cilium/cilium/clustermesh-apiserver/option"
	"github.com/cilium/cilium/clustermesh-apiserver/syncstate"
	"github.com/cilium/cilium/clustermesh-apiserver/version"
	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/cmdref"
	"github.com/cilium/cilium/pkg/controller"
	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/gops"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/kvstore"
	"github.com/cilium/cilium/pkg/kvstore/store"
	"github.com/cilium/cilium/pkg/pprof"
)

var commonCell = cell.Module(
	"clustermesh-common",
	"Common Cilium ClusterMesh modules",
	cell.Config(option.DefaultLegacyClusterMeshConfig),
	cell.Config(cmtypes.DefaultClusterInfo),
	cell.Config(pprofConfig),

	pprof.Cell,
	gops.Cell(defaults.EnableGops, defaults.GopsPortApiserver),

	health.HealthAPIServerCell,

	cmmetrics.Cell,
	controller.Cell,
	kvstore.Cell,
	store.Cell,

	cell.Provide(func(ss syncstate.SyncState) *kvstore.ExtraOptions {
		return &kvstore.ExtraOptions{
			BootstrapComplete: ss.WaitChannel(),
		}
	}),
)

func main() {
	cmd := &cobra.Command{
		Use:   "clustermesh-apiserver",
		Short: "Run the ClusterMesh apiserver",
	}

	cmd.AddCommand(
		cmdref.NewCmd(cmd),
		version.NewCmd(),
		// etcd init does not use the Hive framework, because it's a "one and done" process that doesn't spawn a service
		// or server, or perform any waiting for connections.
		etcdinit.NewCmd(),
		clustermesh.NewCmd(hive.New(commonCell, clustermesh.Cell)),
		kvstoremesh.NewCmd(hive.New(commonCell, kvstoremesh.Cell)),
		clustermeshdbg.RootCmd,
		kvstoremeshdbg.RootCmd,
	)

	if err := cmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

var pprofConfig = pprof.Config{
	Pprof:        false,
	PprofAddress: option.PprofAddress,
	PprofPort:    option.PprofPortClusterMesh,
}
