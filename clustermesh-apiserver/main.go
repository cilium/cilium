// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/cilium/cilium/clustermesh-apiserver/clustermesh"
	clustermeshdbg "github.com/cilium/cilium/clustermesh-apiserver/clustermesh-dbg"
	"github.com/cilium/cilium/clustermesh-apiserver/etcdinit"
	"github.com/cilium/cilium/clustermesh-apiserver/kvstoremesh"
	kvstoremeshdbg "github.com/cilium/cilium/clustermesh-apiserver/kvstoremesh-dbg"
	"github.com/cilium/cilium/clustermesh-apiserver/version"
	"github.com/cilium/cilium/pkg/hive"
)

func main() {
	cmd := &cobra.Command{
		Use:   "clustermesh-apiserver",
		Short: "Run the ClusterMesh apiserver",
	}

	cmd.AddCommand(
		version.NewCmd(),
		// etcd init does not use the Hive framework, because it's a "one and done" process that doesn't spawn a service
		// or server, or perform any waiting for connections.
		etcdinit.NewCmd(),
		clustermesh.NewCmd(hive.New(clustermesh.Cell)),
		kvstoremesh.NewCmd(hive.New(kvstoremesh.Cell)),
		clustermeshdbg.RootCmd,
		kvstoremeshdbg.RootCmd,
	)

	if err := cmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
