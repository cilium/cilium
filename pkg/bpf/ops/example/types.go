// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package main

import (
	"encoding"
	"encoding/binary"

	"github.com/cilium/cilium/pkg/statedb"
	"github.com/cilium/cilium/pkg/statedb/index"
	"github.com/cilium/cilium/pkg/statedb/reconciler"
)

type ExampleKey struct {
	ID uint64
}

func (e ExampleKey) MarshalBinary() ([]byte, error) {
	return binary.NativeEndian.AppendUint64(nil, e.ID), nil
}

type ExampleValue struct {
	X uint64
}

func (e ExampleValue) MarshalBinary() ([]byte, error) {
	return binary.NativeEndian.AppendUint64(nil, e.X), nil
}

type Example struct {
	ExKey   ExampleKey
	ExValue ExampleValue
	Status  reconciler.Status
}

func (e *Example) Key() encoding.BinaryMarshaler {
	return e.ExKey
}

func (e *Example) Value() encoding.BinaryMarshaler {
	return e.ExValue
}

func (e *Example) GetStatus() reconciler.Status {
	return e.Status
}

func (e *Example) WithStatus(newStatus reconciler.Status) *Example {
	return &Example{
		ExKey:   e.ExKey,
		ExValue: e.ExValue,
		Status:  newStatus,
	}
}

var ExampleIDIndex = statedb.Index[*Example, uint64]{
	Name: "id",
	FromObject: func(ex *Example) index.KeySet {
		return index.NewKeySet(index.Uint64(ex.ExKey.ID))
	},
	FromKey: index.Uint64,
	Unique:  true,
}

var ExampleStatusIndex = reconciler.NewStatusIndex[*Example]((*Example).GetStatus)

func NewExampleTable(db *statedb.DB) (statedb.RWTable[*Example], statedb.Index[*Example, reconciler.StatusKind], error) {
	tbl, err := statedb.NewTable[*Example](
		"example",
		ExampleIDIndex,
	)
	if err == nil {
		err = db.RegisterTable(tbl)
	}
	return tbl, ExampleStatusIndex, err
}
