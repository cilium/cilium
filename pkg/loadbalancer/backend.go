// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package loadbalancer

import (
	"fmt"
	"iter"
	"strings"

	"github.com/cilium/statedb"
	"github.com/cilium/statedb/index"

	"github.com/cilium/cilium/pkg/source"
	"github.com/cilium/cilium/pkg/time"
)

const (
	BackendTableName = "backends"
)

// Backend defines a load-balancer backend.
// Stored in the backends table and key'd by (ServiceName, Address, sourcePriority).
// +deepequal-gen=true
// +deepequal-gen:private-method=true
type Backend struct {
	// ServiceName is the service to which this backend is associated to.
	// This field is filled in by the [writer.Writer].
	ServiceName ServiceName

	// Address of the backend.
	Address L3n4Addr

	// PortNames are the optional names for the ports. A frontend can specify which
	// backends to select by port name.
	PortNames []string

	// Weight of backend for load-balancing.
	Weight uint16

	// Node hosting this backend. This is used to determine backends local to
	// a node.
	NodeName string

	// Zone where backend is located.
	Zone string

	// ForZones where this backend should be consumed in
	ForZones []string

	// ClusterID of the cluster in which the backend is located. 0 for local cluster.
	ClusterID uint32

	// Source of the backend.
	Source source.Source

	// State of the backend, e.g. active, quarantined or terminating.
	State BackendState

	// Unhealthy marks a backend as unhealthy and overrides [State] to mark the backend
	// as quarantined. We require a separate field for active health checking to merge
	// with the original source of this backend. Negative is used here to allow the
	// zero value to mean that the backend is healthy.
	Unhealthy bool

	// UnhealthyUpdatedAt is the timestamp for when [Unhealthy] was last updated. Zero
	// value if never updated.
	// +deepequal-gen=false
	UnhealthyUpdatedAt time.Time

	// sourcePriority is the priority of [Source]. Filled in by the [writer.Writer].
	// This along with [ServiceName] and [Address] form the unique primary key ([BackendKey])
	// for the backends table.
	sourcePriority uint8
}

func (be *Backend) GetZone() string {
	return be.Zone
}

func (be *Backend) DeepEqual(other *Backend) bool {
	return be.deepEqual(other) &&
		be.UnhealthyUpdatedAt.Equal(other.UnhealthyUpdatedAt)
}

func (be *Backend) SourcePriority() uint8 {
	return be.sourcePriority
}

func (be *Backend) SetSourcePriority(priority uint8) {
	be.sourcePriority = priority
}

type BackendKey struct {
	ServiceName    ServiceName
	Address        L3n4Addr
	SourcePriority uint8
}

func (k BackendKey) Key() index.Key {
	const separator = 0x00
	key := make([]byte, 0, len(k.ServiceName.Key())+1+len(k.Address.Bytes())+1+1)
	key = append(key, k.ServiceName.Key()...)
	key = append(key, separator)
	key = append(key, k.Address.Bytes()...)
	key = append(key, separator)
	key = append(key, k.SourcePriority)
	return key
}

func (be *Backend) Key() index.Key {
	return BackendKey{
		ServiceName:    be.ServiceName,
		Address:        be.Address,
		SourcePriority: be.sourcePriority,
	}.Key()
}

// IsAlive returns true if this backend instance is marked active or terminating and healthy.
func (be *Backend) IsAlive() bool {
	if be.Unhealthy {
		return false
	}
	return be.State == BackendStateActive || be.State == BackendStateTerminating
}

func (be *Backend) String() string {
	return strings.Join(be.TableRow(), " ")
}

func (be *Backend) TableHeader() []string {
	return []string{
		"Service",
		"Address",
		"Source",
		"Priority",
		"State",
		"PortNames",
		"NodeName",
	}
}

func (be *Backend) TableRow() []string {
	state, _ := be.State.String()
	return []string{
		be.ServiceName.String(),
		be.Address.StringWithProtocol(),
		string(be.Source),
		fmt.Sprintf("%d", be.sourcePriority),
		state,
		strings.Join(be.PortNames, ","),
		be.NodeName,
	}
}

// Clone returns a shallow clone of the backend.
func (be *Backend) Clone() *Backend {
	be2 := *be
	return &be2
}

var (
	backendKeyIndex = statedb.Index[*Backend, BackendKey]{
		Name: "key",
		FromObject: func(be *Backend) index.KeySet {
			return index.NewKeySet(be.Key())
		},
		FromKey: BackendKey.Key,
		Unique:  true,
	}

	BackendByKey = backendKeyIndex.Query

	backendAddrIndex = statedb.Index[*Backend, L3n4Addr]{
		Name: "address",
		FromObject: func(be *Backend) index.KeySet {
			return index.NewKeySet(be.Address.Bytes())
		},
		FromKey:    L3n4Addr.Key,
		FromString: L3n4AddrFromString,
		Unique:     false,
	}

	BackendByAddress = backendAddrIndex.Query
)

func NewBackendsTable(db *statedb.DB) (statedb.RWTable[*Backend], error) {
	tbl, err := statedb.NewTable(
		BackendTableName,
		backendKeyIndex,
		backendAddrIndex,
	)
	if err != nil {
		return nil, err
	}
	return tbl, db.RegisterTable(tbl)
}

var queryFromRawKey = func() func(index.Key) statedb.Query[*Backend] {
	idx := statedb.Index[*Backend, index.Key]{
		Name:       backendKeyIndex.Name,
		FromObject: backendKeyIndex.FromObject,
		FromKey:    func(k index.Key) index.Key { return k },
		Unique:     true,
	}
	return func(k index.Key) statedb.Query[*Backend] {
		return idx.Query(k)
	}
}()

// ListBackendsByServiceName returns backends associated with the given service and a watch channel that closes when
// the associations change.
func ListBackendsByServiceName(txn statedb.ReadTxn, backends statedb.Table[*Backend], name ServiceName) (iter.Seq2[*Backend, statedb.Revision], <-chan struct{}) {
	key := name.Key()
	prefix := make([]byte, len(key)+1 /* the 0x00 separator */)
	copy(prefix, key)
	// Prefix search for "<name>\0" to find all backends associated with the given service.
	return backends.PrefixWatch(txn, queryFromRawKey(index.Key(prefix)))
}

// ListBackendsByServiceNameAndAddress returns backends associated with the given service and address
// and a watch channel that closes when the associations change.
func ListBackendsByServiceNameAndAddress(txn statedb.ReadTxn, backends statedb.Table[*Backend], name ServiceName, addr L3n4Addr) (iter.Seq2[*Backend, statedb.Revision], <-chan struct{}) {
	// Prefix search for "<name>\0<addr>\0" to find all source-priority instances for this backend.
	nameKey := name.Key()
	addrKey := addr.Bytes()
	prefix := make([]byte, 0, len(nameKey)+1+len(addrKey)+1)
	prefix = append(prefix, nameKey...)
	prefix = append(prefix, 0x00)
	prefix = append(prefix, addrKey...)
	prefix = append(prefix, 0x00)
	return backends.PrefixWatch(txn, queryFromRawKey(index.Key(prefix)))
}

// PreferredBackendsByAddress yields only the preferred backend instance per address.
// This relies on BackendKey ordering which sorts by service, then address, then
// source priority (lower is preferred).
func PreferredBackendsByAddress(seq iter.Seq2[*Backend, statedb.Revision]) iter.Seq2[*Backend, statedb.Revision] {
	return func(yield func(*Backend, statedb.Revision) bool) {
		var (
			lastAddr L3n4Addr
			hasAddr  bool
		)
		for be, rev := range seq {
			if !hasAddr || be.Address != lastAddr {
				lastAddr = be.Address
				hasAddr = true
				if !yield(be, rev) {
					return
				}
			}
		}
	}
}
