package lbmap

import (
	"encoding"
	"encoding/gob"
	"encoding/json"

	"github.com/cilium/cilium/pkg/bpf/ops"
	"github.com/cilium/cilium/pkg/statedb"
	"github.com/cilium/cilium/pkg/statedb/index"
	"github.com/cilium/cilium/pkg/statedb/reconciler"
)

func init() {
	// Register types with gob that we want to send over the statedb REST API.
	// This is needed due to the interface indirection (ServiceKey/ServiceValue).
	// TODO: Alternative to this is Service[K,V] to keep everything concrete,
	// or just duplicate code.
	gob.Register(&Service4Key{})
	gob.Register(&Service4Value{})
	gob.Register(&Service6Key{})
	gob.Register(&Service6Value{})
}

var ServiceIndex = statedb.Index[*Service, string]{
	Name: "primary",
	FromObject: func(obj *Service) index.KeySet {
		return index.NewKeySet(index.Stringer(obj.K))
	},
	FromKey: index.String,
	Unique:  true,
}

func newServiceTable(name string) (statedb.RWTable[*Service], error) {
	return statedb.NewTable(
		name,
		ServiceIndex,
	)
}

type (
	Service4Table statedb.RWTable[*Service]
	Service6Table statedb.RWTable[*Service]
)

func NewService4Table(db *statedb.DB) (Service4Table, error) {
	tbl, err := newServiceTable("services4")
	if err == nil {
		return tbl, db.RegisterTable(tbl)
	}
	return nil, err
}

func NewService6Table(db *statedb.DB) (Service6Table, error) {
	tbl, err := newServiceTable("services6")
	if err == nil {
		return tbl, db.RegisterTable(tbl)
	}
	return nil, err
}

type Service struct {
	K      ServiceKey
	V      ServiceValue
	Status reconciler.Status
}

func (s *Service) TableHeader() []string {
	return []string{
		"Key",
		"Value",
		"Status",
	}
}

func (s *Service) TableRow() []string {
	return []string{
		s.K.String(),
		s.V.String(),
		s.Status.String(),
	}
}

func (s *Service) MarshalJSON() ([]byte, error) {
	out := struct {
		Key    string
		Value  string
		Status string
	}{
		Key:    s.K.String(),
		Value:  s.V.String(),
		Status: s.Status.String(),
	}
	return json.Marshal(out)
}

func (s *Service) Key() encoding.BinaryMarshaler {
	return ops.StructBinaryMarshaler{Target: s.K}
}

func (s *Service) Value() encoding.BinaryMarshaler {
	return ops.StructBinaryMarshaler{Target: s.V}
}

func (s *Service) GetStatus() reconciler.Status {
	return s.Status
}

func (s *Service) WithStatus(status reconciler.Status) *Service {
	s2 := *s
	s2.Status = status
	return &s2
}
