// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package reconciler

import (
	"github.com/cilium/statedb"
	"github.com/cilium/statedb/index"
	"github.com/cilium/statedb/reconciler"
)

type EnrolledNamespace struct {
	Name   string
	Status reconciler.Status // reconciliation status
}

// TableHeader implements statedb.TableWritable.
func (ns *EnrolledNamespace) TableHeader() []string {
	return []string{"Name", "Status"}
}

// TableRow implements statedb.TableWritable.
func (ns *EnrolledNamespace) TableRow() []string {
	return []string{ns.Name, ns.Status.String()}
}

var _ statedb.TableWritable = &EnrolledNamespace{}

// GetStatus returns the reconciliation status. Used to provide the
// reconciler access to it.
func (ns EnrolledNamespace) GetStatus() reconciler.Status {
	return ns.Status
}

// SetStatus sets the reconciliation status.
// Used by the reconciler to update the reconciliation status of the EnrolledNamespace.
func (ns *EnrolledNamespace) SetStatus(status reconciler.Status) *EnrolledNamespace {
	ns.Status = status
	return ns
}

// Clone returns a shallow copy of the EnrolledNamespace.
func (ns *EnrolledNamespace) Clone() *EnrolledNamespace {
	e := *ns
	return &e
}

// EnrolledNamespacesNameIndex allows looking up EnrolledNamespace by its name.
var EnrolledNamespacesNameIndex = statedb.Index[*EnrolledNamespace, string]{
	Name: "name",
	FromObject: func(ns *EnrolledNamespace) index.KeySet {
		return index.NewKeySet(index.String(ns.Name))
	},
	FromKey: index.String,
	Unique:  true,
}

func NewEnrolledNamespacesTable(db *statedb.DB) (statedb.RWTable[*EnrolledNamespace], error) {
	return statedb.NewTable(
		db,
		"mtls-enrolled-namespaces",
		EnrolledNamespacesNameIndex,
	)
}
