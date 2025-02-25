// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package k8s

import (
	"github.com/cilium/hive/cell"
	"github.com/cilium/statedb"
	"github.com/cilium/statedb/index"
)

// TablesCell provides a set of StateDB tables for common Kubernetes objects.
// The tables are populated with the StateDB k8s reflector (pkg/k8s/statedb.go).
//
// NOTE: When adding new k8s tables make sure to provide and register from a
// single provider to ensure reflector starts before anyone depending on the table.
// See [NewPodTableAndReflector] for example.
var TablesCell = cell.Module(
	"k8s-tables",
	"StateDB tables of Kubernetes objects",

	PodTableCell,
	NamespaceTableCell,
)

// reflectorName to use in [k8s.ReflectorConfig]. This is the name that appears
// for these tables in the table initializers and is visible in "db" command output
// when the tables are initializing. If a table has multiple reflectors into it
// in this package, append a suffix to [reflectorName].
const reflectorName = "daemon-k8s"

type namer interface {
	GetNamespace() string
	GetName() string
}

func newNameIndex[Obj namer]() statedb.Index[Obj, string] {
	return statedb.Index[Obj, string]{
		Name: "name",
		FromObject: func(obj Obj) index.KeySet {
			if ns := obj.GetNamespace(); ns != "" {
				return index.NewKeySet(index.String(ns + "/" + obj.GetName()))
			}
			return index.NewKeySet(index.String(obj.GetName()))
		},
		FromKey: index.String,
		FromString: func(key string) (index.Key, error) {
			return index.String(key), nil
		},
		Unique: true,
	}
}
