// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package k8s

import (
	"github.com/cilium/hive/cell"
	"github.com/cilium/statedb"
	"github.com/cilium/statedb/index"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// ResourcesCell provides a set of handles to Kubernetes resources used throughout the
// agent. Each of the resources share a client-go informer and backing store so we only
// have one watch API call for each resource kind and that we maintain only one copy of each object.
//
// See pkg/k8s/resource/resource.go for documentation on the Resource[T] type.

// TablesCell provides a set of StateDB tables for common Kubernetes objects.
// The tables are populated with the StateDB k8s reflector (pkg/k8s/statedb.go).
// Some tables are provided as OnDemand[Table[T]]
var TablesCell = cell.Module(
	"k8s-tables",
	"StateDB tables of Kubernetes objects",

	PodTableCell,
)

// reflectorName to use in [k8s.ReflectorConfig]. This is the name that appears
// for these tables in the table initializers and is visible in "db" command output
// when the tables are initializing. If a table has multiple reflectors into it
// in this package, append a suffix to [reflectorName].
const reflectorName = "daemon-k8s"

func newNameIndex[Obj metav1.Object]() statedb.Index[Obj, string] {
	return statedb.Index[Obj, string]{
		Name: "name",
		FromObject: func(obj Obj) index.KeySet {
			return index.NewKeySet(index.String(obj.GetNamespace() + "/" + obj.GetName()))
		},
		FromKey: index.String,
		FromString: func(key string) (index.Key, error) {
			return index.String(key), nil
		},
		Unique: true,
	}
}
