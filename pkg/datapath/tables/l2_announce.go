// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package tables

import (
	"fmt"
	"net"
	"reflect"

	"github.com/cilium/cilium/pkg/k8s/resource"
	"github.com/cilium/cilium/pkg/statedb"

	"github.com/hashicorp/go-memdb"
	"golang.org/x/exp/slices"
)

type L2AnnounceEntry struct {
	// IP and network interface are the primary key of this entry
	IP               net.IP
	NetworkInterface string

	// The key of the services for which this proxy entry was added
	Origins []resource.Key

	Deleted  bool
	Revision uint64
}

func (pne *L2AnnounceEntry) DeepCopy() *L2AnnounceEntry {
	var n L2AnnounceEntry
	n.IP = make(net.IP, len(pne.IP))
	copy(n.IP, pne.IP)
	n.NetworkInterface = pne.NetworkInterface
	n.Origins = slices.Clone(pne.Origins)
	return &n
}

var L2AnnouncementTableCell = statedb.NewTableCell[*L2AnnounceEntry](schema)

func ByProxyIPAndInterface(ip net.IP, iface string) statedb.Query {
	return statedb.Query{
		Index: idIndex,
		Args:  []any{ip, iface},
	}
}

func ByProxyOrigin(originKey resource.Key) statedb.Query {
	return statedb.Query{
		Index: originIndex,
		Args:  []any{originKey},
	}
}

func Deleted() statedb.Query {
	return statedb.Query{
		Index: deletedIndex,
		Args:  []any{true},
	}
}

var (
	idIndex      = statedb.Index("id")
	originIndex  = statedb.Index("byOrigin")
	deletedIndex = statedb.Index("byDeleted")
	schema       = &memdb.TableSchema{
		Name: "l2-announce-entries",
		Indexes: map[string]*memdb.IndexSchema{
			string(idIndex): {
				Name:   string(idIndex),
				Unique: true,
				Indexer: &memdb.CompoundIndex{
					Indexes: []memdb.Indexer{
						&statedb.IPIndexer{Field: "IP"},
						&memdb.StringFieldIndex{Field: "NetworkInterface"},
					},
				},
			},
			string(originIndex): {
				Name:         string(originIndex),
				AllowMissing: true,
				Unique:       false,
				Indexer:      &resourceKeySliceFieldIndex{Field: "Origins"},
			},
			statedb.RevisionIndexSchema.Name: statedb.RevisionIndexSchema,
			string(deletedIndex): {
				Name:         string(deletedIndex),
				AllowMissing: false,
				Unique:       false,
				Indexer:      &memdb.BoolFieldIndex{Field: "Deleted"},
			},
		},
	}
)

type resourceKeySliceFieldIndex struct {
	Field string
}

func (rki *resourceKeySliceFieldIndex) FromObject(obj interface{}) (bool, [][]byte, error) {
	v := reflect.ValueOf(obj)
	v = reflect.Indirect(v) // Dereference the pointer if any

	fv := v.FieldByName(rki.Field)
	if !fv.IsValid() {
		return false, nil,
			fmt.Errorf("field '%s' for %#v is invalid", rki.Field, obj)
	}

	if fv.Kind() != reflect.Slice || fv.Type().Elem() != reflect.TypeOf(resource.Key{}) {
		return false, nil, fmt.Errorf("field '%s' is not a resource.Key slice", rki.Field)
	}

	length := fv.Len()
	vals := make([][]byte, 0, length)
	for i := 0; i < fv.Len(); i++ {
		val := fv.Index(i).Interface().(resource.Key).String()

		// Add the null character as a terminator
		val += "\x00"
		vals = append(vals, []byte(val))
	}
	if len(vals) == 0 {
		return false, nil, nil
	}
	return true, vals, nil
}

func (rki *resourceKeySliceFieldIndex) FromArgs(args ...interface{}) ([]byte, error) {
	if len(args) != 1 {
		return nil, fmt.Errorf("must provide only a single argument")
	}

	switch arg := args[0].(type) {
	case string:
		return []byte(arg + "\x00"), nil
	case resource.Key:
		return []byte(arg.String() + "\x00"), nil
	default:
		return nil, fmt.Errorf("argument must be a string or resource.Key: %#v", args[0])
	}
}

func (rki *resourceKeySliceFieldIndex) PrefixFromArgs(args ...interface{}) ([]byte, error) {
	val, err := rki.FromArgs(args...)
	if err != nil {
		return nil, err
	}

	// Strip the null terminator, the rest is a prefix
	n := len(val)
	if n > 0 {
		return val[:n-1], nil
	}
	return val, nil
}
