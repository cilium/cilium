// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package k8s

import (
	"github.com/cilium/cilium/pkg/k8s"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	"github.com/cilium/hive/cell"
	"github.com/cilium/statedb"
	"github.com/cilium/statedb/index"
)

// TablesCell provides the statedb tables for Kubernetes objects.
// It's a private cell that can be imported by other cells in this package.
var TablesCell = cell.Module(
	"k8s-tables",
	"statedb tables for Kubernetes objects",

	SvcEPTablesCell,
	PodTableCell,
	NamespaceTableCell,

	cell.Provide(
		statedb.RWTable[*slim_corev1.Service].ToTable,
		statedb.RWTable[*k8s.Endpoints].ToTable,
		statedb.RWTable[LocalPod].ToTable,
	),
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
