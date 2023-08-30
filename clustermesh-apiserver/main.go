// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/cilium/cilium/clustermesh-apiserver/clustermesh"
	"github.com/cilium/cilium/pkg/hive"
)

func main() {
	cmd := &cobra.Command{
		Use:   "clustermesh-apiserver",
		Short: "Run the ClusterMesh apiserver",
	}

	cmd.AddCommand(
		clustermesh.NewCmd(hive.New(clustermesh.Cell)),
	)

	if err := cmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
