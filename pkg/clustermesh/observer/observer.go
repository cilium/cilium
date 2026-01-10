// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package observer

import (
	"github.com/cilium/hive/cell"

	"github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/kvstore"
	"github.com/cilium/cilium/pkg/kvstore/store"
)

// Name represents the name of an observer.
type Name string

// Observer knows how to watch a prefix from a given etcd instance.
type Observer interface {
	// Name returns the name of the observer.
	Name() Name

	// Status returns the status of the observer.
	Status() Status

	// Register registers the observer with the given [store.WatchStoreManager], to
	// watch the desired prefix. If the observer is not enabled (e.g., as not supported
	// according to the remote cluster capabilities), it drains possibly stale data.
	Register(mgr store.WatchStoreManager, backend kvstore.BackendOperations, cfg types.CiliumClusterConfig)

	// Drain emits a deletion event for all previously observed entries, upon
	// disconnection from the target remote cluster.
	Drain()

	// Revoke possibly emits a deletion event for all previously observed entries,
	// if connectivity to the target remote cluster is lost.
	Revoke()
}

// Status summarizes the status of an observer.
type Status struct {
	// Enabled represents whether the observer is currently enabled.
	Enabled bool

	// Synced represents whether the observer retrieved the initial list of entries from etcd.
	Synced bool

	// Entries is the number of entries observed by the given observer.
	Entries uint64
}

// Factory is the signature of the observer factory.
type Factory func(cluster string, onSync func()) Observer

// NewFactoryOut provides the given factory via Hive.
func NewFactoryOut(factory Factory) FactoryOut {
	return FactoryOut{Factory: factory}
}

type FactoryOut struct {
	cell.Out

	Factory Factory `group:"clustermesh-observers"`
}
