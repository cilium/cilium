// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package main

import (
	"context"
	"fmt"

	"github.com/cilium/cilium/pkg/statedb"
	"github.com/cilium/cilium/pkg/statedb/example/tables"
	"github.com/cilium/cilium/pkg/statedb/grpc"
)

func main() {
	client, err := statedb.NewClient("localhost:8456")
	if err != nil {
		panic(err)
	}

	resp, err := client.Meta(context.TODO(), &grpc.MetaRequest{})
	if err != nil {
		panic(err)
	}

	fmt.Printf("Tables:\n")
	for _, table := range resp.Table {
		fmt.Printf("\t%s with indexes %v\n", table.Name, table.Index)
	}

	table := statedb.NewRemoteTable[tables.Backend](client, "backends")
	if err != nil {
		panic(err)
	}

	iter, err := table.Watch(context.TODO())
	if err != nil {
		panic(err)
	}

	for obj, deleted, _, ok := iter.Next(); ok; obj, deleted, _, ok = iter.Next() {
		if !deleted {
			fmt.Printf("Update: %+v\n", obj)
		} else {
			fmt.Printf("Delete: %+v\n", obj)
		}
	}
}
