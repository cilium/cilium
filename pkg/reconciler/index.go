package reconciler

import (
	"github.com/cilium/cilium/pkg/statedb"
	"github.com/cilium/cilium/pkg/statedb/index"
)

func NewStatusIndex[Obj Reconcilable[Obj]]() statedb.Index[Obj, StatusKind] {
	return statedb.Index[Obj, StatusKind]{
		Name: "status",
		FromObject: func(obj Obj) index.KeySet {
			return index.NewKeySet(index.String(string(obj.GetStatus().Kind)))
		},
		FromKey: func(k StatusKind) index.Key {
			return index.String(string(k))
		},
		Unique: false,
	}
}
