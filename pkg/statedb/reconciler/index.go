// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package reconciler

import (
	"github.com/cilium/cilium/pkg/statedb"
	"github.com/cilium/cilium/pkg/statedb/index"
)

// NewStatusIndex creates a status index for a table of reconcilable objects.
func NewStatusIndex[Obj any](getObjectStatus func(Obj) Status) statedb.Index[Obj, StatusKind] {
	return statedb.Index[Obj, StatusKind]{
		Name: "status",
		FromObject: func(obj Obj) index.KeySet {
			return index.NewKeySet(index.String(string(getObjectStatus(obj).Kind)))
		},
		FromKey: func(k StatusKind) index.Key {
			return index.String(string(k))
		},
		Unique: false,
	}
}
