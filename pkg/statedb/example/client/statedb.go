// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package main

import (
	"context"
	"fmt"

	"github.com/cilium/cilium/pkg/statedb"
	"github.com/cilium/cilium/pkg/statedb/example/tables"
)

func main() {
	table, err := statedb.NewRemoteTable[tables.Backend]("backends", "localhost:8456")
	if err != nil {
		panic(err)
	}

	iter, err := table.Watch(context.TODO())
	if err != nil {
		panic(err)
	}

	for obj, _, ok := iter.Next(); ok; obj, _, ok = iter.Next() {
		fmt.Printf("%+v\n", obj)
	}
}
