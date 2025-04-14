// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/cilium/cilium/clustermesh-apiserver/clustermesh"
	clustermeshdbg "github.com/cilium/cilium/clustermesh-apiserver/clustermesh-dbg"
	"github.com/cilium/cilium/clustermesh-apiserver/common"
	"github.com/cilium/cilium/clustermesh-apiserver/etcdinit"
	"github.com/cilium/cilium/clustermesh-apiserver/kvstoremesh"
	kvstoremeshdbg "github.com/cilium/cilium/clustermesh-apiserver/kvstoremesh-dbg"
	"github.com/cilium/cilium/clustermesh-apiserver/version"
	"github.com/cilium/cilium/pkg/cmdref"
	"github.com/cilium/cilium/pkg/hive"
)

var RootCmd = &cobra.Command{
	Use:   "clustermesh-apiserver",
	Short: "Run the ClusterMesh apiserver",
}

func init() {
	RootCmd.AddCommand(
		cmdref.NewCmd(RootCmd),
		version.NewCmd(),
		// etcd init does not use the Hive framework, because it's a "one and done" process that doesn't spawn a service
		// or server, or perform any waiting for connections.
		etcdinit.NewCmd(),
		clustermesh.NewCmd(hive.New(common.Cell, clustermesh.Cell)),
		kvstoremesh.NewCmd(hive.New(common.Cell, kvstoremesh.Cell)),
		clustermeshdbg.RootCmd,
		kvstoremeshdbg.RootCmd,
	)
}

func Execute() {
	if err := RootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
