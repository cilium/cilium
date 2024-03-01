package lbmap

import (
	"encoding"
	"encoding/gob"
	"encoding/json"

	"github.com/cilium/cilium/pkg/bpf/ops"
	"github.com/cilium/cilium/pkg/loadbalancer"
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

	gob.Register(&Backend4KeyV3{})
	gob.Register(&Backend4ValueV3{})
	gob.Register(&Backend6KeyV3{})
	gob.Register(&Backend6ValueV3{})

	gob.Register(&RevNat4Key{})
	gob.Register(&RevNat4Value{})
	gob.Register(&RevNat6Key{})
	gob.Register(&RevNat6Value{})
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

var BackendIndex = statedb.Index[*BackendKV, loadbalancer.BackendID]{
	Name: "primary",
	FromObject: func(obj *BackendKV) index.KeySet {
		return index.NewKeySet(index.Uint32(uint32(obj.K.GetID())))
	},
	FromKey: func(id loadbalancer.BackendID) index.Key {
		return index.Uint32(uint32(id))
	},
	Unique: true,
}

func newBackendTable(name string) (statedb.RWTable[*BackendKV], error) {
	return statedb.NewTable(
		name,
		BackendIndex,
	)
}

type (
	Backend4Table statedb.RWTable[*BackendKV]
	Backend6Table statedb.RWTable[*BackendKV]
)

func NewBackend4Table(db *statedb.DB) (Backend4Table, error) {
	tbl, err := newBackendTable("backends4")
	if err == nil {
		return tbl, db.RegisterTable(tbl)
	}
	return nil, err
}

func NewBackend6Table(db *statedb.DB) (Backend6Table, error) {
	tbl, err := newBackendTable("backends6")
	if err == nil {
		return tbl, db.RegisterTable(tbl)
	}
	return nil, err
}

// TODO: "Backend" was already in use, but this name sucks.
type BackendKV struct {
	K      BackendKey
	V      BackendValue
	Status reconciler.Status
}

func (s *BackendKV) TableHeader() []string {
	return []string{
		"Key",
		"Value",
		"Status",
	}
}

func (s *BackendKV) TableRow() []string {
	return []string{
		s.K.String(),
		s.V.String(),
		s.Status.String(),
	}
}

func (s *BackendKV) MarshalJSON() ([]byte, error) {
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

func (s *BackendKV) Key() encoding.BinaryMarshaler {
	return ops.StructBinaryMarshaler{Target: s.K}
}

func (s *BackendKV) Value() encoding.BinaryMarshaler {
	return ops.StructBinaryMarshaler{Target: s.V}
}

func (s *BackendKV) GetStatus() reconciler.Status {
	return s.Status
}

func (s *BackendKV) WithStatus(status reconciler.Status) *BackendKV {
	s2 := *s
	s2.Status = status
	return &s2
}

type (
	RevNat4Table statedb.RWTable[*RevNat]
	RevNat6Table statedb.RWTable[*RevNat]
)

var RevNatIndex = statedb.Index[*RevNat, uint16]{
	Name: "primary",
	FromObject: func(obj *RevNat) index.KeySet {
		return index.NewKeySet(index.Uint16(obj.K.GetKey()))
	},
	FromKey: func(id uint16) index.Key {
		return index.Uint16(id)
	},
	Unique: true,
}

func newRevNatTable(name string) (statedb.RWTable[*RevNat], error) {
	return statedb.NewTable(
		name,
		RevNatIndex,
	)
}

func NewRevNat4Table(db *statedb.DB) (RevNat4Table, error) {
	tbl, err := newRevNatTable("revnat4")
	if err == nil {
		return tbl, db.RegisterTable(tbl)
	}
	return nil, err
}

func NewRevNat6Table(db *statedb.DB) (RevNat6Table, error) {
	tbl, err := newRevNatTable("revnat6")
	if err == nil {
		return tbl, db.RegisterTable(tbl)
	}
	return nil, err
}

type RevNat struct {
	K      RevNatKey
	V      RevNatValue
	Status reconciler.Status
}

func (s *RevNat) TableHeader() []string {
	return []string{
		"Key",
		"Value",
		"Status",
	}
}

func (s *RevNat) TableRow() []string {
	return []string{
		s.K.String(),
		s.V.String(),
		s.Status.String(),
	}
}

func (s *RevNat) MarshalJSON() ([]byte, error) {
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

func (s *RevNat) Key() encoding.BinaryMarshaler {
	return ops.StructBinaryMarshaler{Target: s.K}
}

func (s *RevNat) Value() encoding.BinaryMarshaler {
	return ops.StructBinaryMarshaler{Target: s.V}
}

func (s *RevNat) GetStatus() reconciler.Status {
	return s.Status
}

func (s *RevNat) WithStatus(status reconciler.Status) *RevNat {
	s2 := *s
	s2.Status = status
	return &s2
}
