package datapath

import (
	"encoding"
	"encoding/binary"
	"fmt"
	"net/netip"

	"github.com/cilium/cilium/pkg/statedb/index"
	"github.com/cilium/cilium/pkg/statedb/reconciler"
)

type ID uint64

const IDSize = 8

func (id ID) MarshalBinary() ([]byte, error) {
	buf := make([]byte, 8)
	binary.NativeEndian.PutUint64(buf, uint64(id))
	return buf, nil
}

type FrontendID = ID

type FrontendMeta struct {
	Name     string
	Addr     netip.Addr
	Protocol L4Proto
	Port     uint16
	Type     string
}

type Frontend struct {
	FrontendMeta

	ID FrontendID

	Backends ImmSet[BackendID]

	Status reconciler.Status
}

func (fe *Frontend) Clone() *Frontend {
	// Since all fields are immutable value types in Frontend, we can
	// just make a simple shallow copy.
	fe2 := *fe
	return &fe2
}

func (fe *Frontend) WithBackends(bes ImmSet[BackendID]) *Frontend {
	fe = fe.Clone()
	fe.Backends = bes
	return fe
}

func (fe *Frontend) Key() encoding.BinaryMarshaler {
	return fe.ID
}

func (fe *Frontend) Value() encoding.BinaryMarshaler {
	return fe
}

const (
	maxBackends     = 16
	maxFrontendSize = 16 /* addr */ + 1 /* proto */ + 1 /* len backends */ + 16*backendSize
	backendSize     = 16 /* addr */ + 1 /* proto */ + 2 /* port */
)

func (fe *Frontend) MarshalBinary() ([]byte, error) {
	buf := make([]byte, 0, maxFrontendSize)
	buf = append(buf, fe.Addr.AsSlice()...)
	if b, err := fe.Protocol.MarshalBinary(); err == nil {
		buf = append(buf, b...)
	} else {
		return nil, err
	}
	buf = append(buf, byte(len(fe.Backends)))
	for _, id := range fe.Backends {
		if b, err := id.MarshalBinary(); err == nil {
			buf = append(buf, b...)
		} else {
			return nil, err
		}
	}
	return buf[0:maxFrontendSize], nil
}

type BackendID = ID

type BackendKey struct {
	Addr     netip.Addr
	Protocol L4Proto
	Port     uint16
}

func (k BackendKey) IndexKey() index.Key {
	buf := make([]byte, 0, 16+3+2)
	buf = append(buf, index.NetIPAddr(k.Addr)...)
	buf = append(buf, index.String(string(k.Protocol))...)
	buf = append(buf, index.Uint16(k.Port)...)
	return buf
}

type Backend struct {
	BackendKey
	ID     BackendID
	Refs   ImmSet[string]
	Status reconciler.Status
}

func (be *Backend) Clone() *Backend {
	be2 := *be
	return &be2
}

func (be *Backend) MarshalBinary() ([]byte, error) {
	buf := make([]byte, 0, backendSize)
	addr := be.Addr.As16()
	buf = append(buf, addr[:]...)
	if b, err := be.Protocol.MarshalBinary(); err == nil {
		buf = append(buf, b...)
	} else {
		return nil, err
	}
	buf = binary.NativeEndian.AppendUint16(buf, be.Port)
	return buf, nil
}

func (be *Backend) Key() encoding.BinaryMarshaler {
	return be.ID
}

func (be *Backend) Value() encoding.BinaryMarshaler {
	return be
}

type L4Proto string

func (l4 L4Proto) MarshalBinary() ([]byte, error) {
	switch l4 {
	case TCP:
		return []byte{0}, nil
	case UDP:
		return []byte{1}, nil
	}
	return nil, fmt.Errorf("unknown proto: %q", l4)
}

const (
	TCP = L4Proto("TCP")
	UDP = L4Proto("UDP")
)
