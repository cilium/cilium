// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package statedb

import (
	"fmt"
	"net"
	"reflect"

	memdb "github.com/hashicorp/go-memdb"
)

// Common index schemas
var (
	UUIDIndex       = Index("id")
	UUIDIndexSchema = &memdb.IndexSchema{
		Name:         string(UUIDIndex),
		AllowMissing: false,
		Unique:       true,
		Indexer:      &memdb.UUIDFieldIndex{Field: "UUID"},
	}

	RevisionIndex       = Index("revision")
	RevisionIndexSchema = &memdb.IndexSchema{
		Name:         string(RevisionIndex),
		AllowMissing: false,
		Unique:       false,
		Indexer:      &memdb.UintFieldIndex{Field: "Revision"},
	}

	IPIndex  = Index("ip")
	IPSchema = &memdb.IndexSchema{
		Name:         string(IPIndex),
		AllowMissing: false,
		Unique:       false,
		Indexer:      &IPIndexer{Field: "IP"},
	}
)

type IPIndexer struct {
	Field string
}

var ipType = reflect.TypeOf(net.IP{})

func (ii *IPIndexer) FromObject(obj interface{}) (bool, []byte, error) {
	v := reflect.ValueOf(obj)
	v = reflect.Indirect(v) // Dereference the pointer if any

	fv := v.FieldByName(ii.Field)
	if !fv.IsValid() {
		return false, nil,
			fmt.Errorf("field '%s' for %#v is invalid", ii.Field, obj)
	}

	var ip net.IP

	if fv.Type() == ipType {
		ip = fv.Interface().(net.IP)
	} else {
		ip = net.ParseIP(fv.String())
	}

	return true, []byte(ip), nil
}

func (ii *IPIndexer) FromArgs(args ...interface{}) ([]byte, error) {
	if len(args) != 1 {
		return nil, fmt.Errorf("must provide only a single argument")
	}
	switch arg := args[0].(type) {
	case string:
		return net.ParseIP(arg), nil
	case net.IP:
		return arg, nil
	case []byte:
		if len(arg) != net.IPv4len || len(arg) != net.IPv6len {
			return nil, fmt.Errorf("byte slice must represent an IPv4 or IPv6 address")
		}
		return arg, nil
	default:
		return nil,
			fmt.Errorf("argument must be a net.IP, string or byte slice: %#v", args[0])
	}
}

func (ii *IPIndexer) PrefixFromArgs(args ...interface{}) ([]byte, error) {
	if len(args) != 1 {
		return nil, fmt.Errorf("must provide only a single argument")
	}
	switch arg := args[0].(type) {
	case string:
		return net.ParseIP(arg), nil
	case net.IP:
		return arg, nil
	case []byte:
		return arg, nil
	default:
		return nil,
			fmt.Errorf("argument must be a net.IP, string or byte slice: %#v", args[0])
	}
}
